package org.matrix.teesim

import java.io.ByteArrayInputStream
import java.io.File
import java.io.StringReader
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import javax.xml.parsers.DocumentBuilderFactory
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.json.JSONArray
import org.json.JSONObject
import org.w3c.dom.Element

/**
 * Parses a keybox.xml for the WebUI's keybox inspector. For each `<Key algorithm>` block it decodes
 * the certificate chain and reports the fields that let a user spot a bad keybox — subject/issuer,
 * validity (with expiry), key type and size, and whether the chain links up — plus whether a
 * private key is present. Read-only: the private key material is never returned, only that it
 * exists.
 *
 * It also runs the checks that decide whether a keybox would pass Play Integrity / hardware
 * attestation: each cert's signature is verified against its parent, [RootPublicKey] classifies the
 * root the chain terminates in (Google, AOSP software, Knox, or unknown), and every serial is
 * looked up in Google's revocation list ([RevocationList]). A Google-rooted, cryptographically
 * linked, unrevoked chain is a genuine live keybox; a revoked or software-rooted one is not.
 */
object KeyboxInspector {

    private val NAME_RE = Regex("^[A-Za-z0-9._-]+\\.xml$")

    /**
     * Coerce to a safe *.xml basename inside the module dir, or null. Mirrors the WebUI's safeName.
     */
    private fun safeName(raw: String): String? {
        val name = raw.trim().substringAfterLast('/').substringAfterLast('\\')
        if (name.isEmpty() || name.contains("..") || !NAME_RE.matches(name)) return null
        return name
    }

    /**
     * Validate an untrusted keybox before the WebUI writes it to the canonical data directory.
     * The check is deliberately capability-based: RSA-only and EC-only keyboxes are valid, while
     * duplicate algorithms, missing private keys, malformed chains, mismatched private/public keys,
     * or broken certificate signatures are rejected. Trust/revocation is presentation metadata and
     * is therefore not an import gate.
     */
    fun validateText(xmlText: String): JSONObject {
        if (xmlText.isBlank()) return fail("keybox is empty")
        if (xmlText.toByteArray(Charsets.UTF_8).size > 2 * 1024 * 1024) {
            return fail("keybox exceeds 2 MiB validation limit")
        }
        return try {
            val doc =
                newSafeBuilder()
                    .parse(ByteArrayInputStream(xmlText.toByteArray(Charsets.UTF_8)))
            val root = doc.documentElement
            val scope = firstChild(root, "Keybox") ?: root
            val keyNodes = scope.getElementsByTagName("Key")
            val seen = HashSet<String>()
            val keys = JSONArray()
            val warnings = JSONArray()
            var hasRsa = false
            var hasEc = false
            for (i in 0 until keyNodes.length) {
                val ke = keyNodes.item(i) as? Element ?: continue
                val algorithm = ke.getAttribute("algorithm").trim().lowercase()
                if (algorithm != "rsa" && algorithm != "ecdsa") {
                    warnings.put("ignored unsupported Key algorithm: ${algorithm.ifBlank { "?" }}")
                    continue
                }
                if (!seen.add(algorithm)) {
                    return fail("duplicate <Key algorithm=\"$algorithm\"> block")
                }
                keys.put(validateKey(ke, algorithm))
                if (algorithm == "rsa") hasRsa = true else hasEc = true
            }
            if (!hasRsa && !hasEc) {
                return fail("keybox has no supported RSA or ECDSA signing key")
            }
            JSONObject()
                .put("ok", true)
                .put("capabilities", capabilitiesJson(hasRsa, hasEc))
                .put("keys", keys)
                .put("warnings", warnings)
        } catch (e: Exception) {
            fail("invalid keybox: ${e.message ?: e.javaClass.simpleName}")
        }
    }

    fun inspect(rawName: String, forceRefresh: Boolean = false): JSONObject {
        val name = safeName(rawName) ?: return fail("invalid keybox name")
        val file = File(Const.DATA_DIR, name)
        if (!file.isFile) return fail("no such keybox: $name")
        // Pull-to-refresh on the detail page re-fetches Google's revocation list before
        // re-checking.
        if (forceRefresh) RevocationList.forceRefresh()
        return try {
            val doc = newSafeBuilder().parse(file)
            val root = doc.documentElement
            val kb = firstChild(root, "Keybox")
            val scope = kb ?: root
            val keyNodes = scope.getElementsByTagName("Key")
            val keys = JSONArray()
            var hasRsa = false
            var hasEc = false
            for (i in 0 until keyNodes.length) {
                (keyNodes.item(i) as? Element)?.let {
                    when (it.getAttribute("algorithm").trim().lowercase()) {
                        "rsa" -> hasRsa = true
                        "ecdsa" -> hasEc = true
                    }
                    keys.put(inspectKey(it))
                }
            }
            JSONObject()
                .put("ok", true)
                .put("name", name)
                .put("deviceId", kb?.getAttribute("DeviceID") ?: "")
                .put("revocationListAvailable", RevocationList.available())
                .put("capabilities", capabilitiesJson(hasRsa, hasEc))
                .put("keys", keys)
        } catch (e: Exception) {
            SystemLogger.warning("KeyboxInspector: failed to parse $name", e)
            fail("could not parse keybox: ${e.message}")
        }
    }

    /**
     * Canonical subject-DN -> keybox filename, across every `*.xml` keybox in the module dir. Used
     * to attribute a stored attestation key to the keybox that signed it: the key's leaf
     * certificate is issued by the keybox's signing (batch) cert, whose subject appears here, and
     * the batch/intermediate/ root certs of the key's chain are keybox subjects too — so a hit on
     * either the leaf's issuer or any chain subject names the signer. Best effort: an unparseable
     * keybox simply contributes nothing.
     */
    fun signerIndex(): Map<String, String> {
        val out = HashMap<String, String>()
        val files =
            File(Const.DATA_DIR).listFiles { f -> f.isFile && NAME_RE.matches(f.name) }
                ?: return out
        for (file in files) {
            try {
                val certNodes =
                    newSafeBuilder().parse(file).documentElement.getElementsByTagName("Certificate")
                for (i in 0 until certNodes.length) {
                    val cert = parsePem(certNodes.item(i).textContent) ?: continue
                    out[canonicalDn(cert.subjectX500Principal)] = file.name
                }
            } catch (e: Exception) {
                SystemLogger.warning("KeyboxInspector.signerIndex: skipping ${file.name}", e)
            }
        }
        return out
    }

    /**
     * Every keybox's signing chain as a set of its certificates' canonical subject DNs — one entry
     * per `<Key>` block (a keybox usually holds an ecdsa and an rsa chain), paired with the keybox
     * filename. Used to attribute a stored attestation key to a keybox only when the key's own
     * chain embeds that keybox's WHOLE chain, from the root certificate down through the
     * intermediate to the batch signer. A single shared root/intermediate — as a genuine device key
     * shares with a Google keybox — is not enough, so a coincidental match no longer names a
     * keybox. Best effort: an unparseable keybox or chain simply contributes nothing.
     */
    fun signerChains(): List<Pair<String, Set<String>>> {
        val out = ArrayList<Pair<String, Set<String>>>()
        val files =
            File(Const.DATA_DIR).listFiles { f -> f.isFile && NAME_RE.matches(f.name) }
                ?: return out
        for (file in files) {
            try {
                val root = newSafeBuilder().parse(file).documentElement
                val scope = firstChild(root, "Keybox") ?: root
                val keyNodes = scope.getElementsByTagName("Key")
                for (i in 0 until keyNodes.length) {
                    val ke = keyNodes.item(i) as? Element ?: continue
                    val certParent = firstChild(ke, "CertificateChain") ?: ke
                    val certNodes = certParent.getElementsByTagName("Certificate")
                    val dns = HashSet<String>()
                    for (j in 0 until certNodes.length) {
                        val cert = parsePem(certNodes.item(j).textContent) ?: continue
                        dns.add(canonicalDn(cert.subjectX500Principal))
                    }
                    if (dns.isNotEmpty()) out.add(file.name to dns)
                }
            } catch (e: Exception) {
                SystemLogger.warning("KeyboxInspector.signerChains: skipping ${file.name}", e)
            }
        }
        return out
    }

    /**
     * RFC 2253 canonical form of a DN, so subject/issuer strings compare regardless of encoding
     * quirks.
     */
    fun canonicalDn(p: javax.security.auth.x500.X500Principal): String =
        p.getName(javax.security.auth.x500.X500Principal.CANONICAL)

    private fun inspectKey(ke: Element): JSONObject {
        val out = JSONObject().put("algorithm", ke.getAttribute("algorithm").ifBlank { "?" })

        val priv = firstChild(ke, "PrivateKey")
        out.put("privateKeyPresent", priv != null && priv.textContent.contains("PRIVATE KEY"))

        val certParent = firstChild(ke, "CertificateChain") ?: ke
        val certNodes = certParent.getElementsByTagName("Certificate")

        // Parse every slot; a null keeps its position so the signature pairing (cert[i] signed by
        // cert[i+1], the top cert self-signed) stays aligned even when one cert fails to decode.
        val parsed = ArrayList<X509Certificate?>()
        for (i in 0 until certNodes.length) parsed.add(parsePem(certNodes.item(i).textContent))
        val valid = parsed.filterNotNull()

        val revChecked = RevocationList.available()
        val certs = JSONArray()
        var anyRevoked = false
        var chainVerified = valid.isNotEmpty() && valid.size == parsed.size
        for (i in parsed.indices) {
            val cert = parsed[i]
            if (cert == null) {
                certs.put(JSONObject().put("index", i).put("error", "could not parse certificate"))
                chainVerified = false
                continue
            }
            val j = certJson(i, cert)

            // Cryptographic linkage: every cert is signed by the next one up; a self-signed root
            // signs itself. When the top cert is not self-signed the real root is not embedded (the
            // chain ends at an intermediate) — there is nothing in-chain to check it against, so
            // leave it and let RootPublicKey.authorityOf decide its trust.
            val isTop = i == parsed.size - 1
            val selfSigned = cert.subjectX500Principal == cert.issuerX500Principal
            val parentKey =
                when {
                    isTop && !selfSigned -> null
                    isTop -> cert.publicKey
                    else -> parsed[i + 1]?.publicKey
                }
            val sigValid = parentKey?.let {
                try {
                    cert.verify(it)
                    true
                } catch (_: Exception) {
                    false
                }
            }
            if (sigValid != null) j.put("signatureValid", sigValid)
            if (sigValid == false) chainVerified = false

            j.put("revocationChecked", revChecked)
            if (revChecked) {
                val rev = RevocationList.status(cert.serialNumber)
                if (rev != null) {
                    anyRevoked = true
                    j.put("revoked", true)
                        .put("revocationStatus", rev.optString("status", "REVOKED"))
                        .put("revocationReason", rev.optString("reason", ""))
                } else {
                    j.put("revoked", false)
                }
            }
            certs.put(j)
        }

        val authority = RootPublicKey.authorityOf(valid)
        // Tag the top-most parsed cert with the verdict, so the root row can show it.
        val topIndex = parsed.indexOfLast { it != null }
        if (topIndex >= 0) certs.optJSONObject(topIndex)?.put("rootAuthority", authority)

        out.put("chainLength", certNodes.length)
        out.put("certs", certs)
        out.put("linkage", linkage(valid))
        out.put("rootAuthority", authority)
        out.put("googleSigned", authority == RootPublicKey.GOOGLE)
        out.put("chainVerified", chainVerified)
        out.put("revoked", anyRevoked)
        out.put("revocationChecked", revChecked)
        return out
    }

    private fun capabilitiesJson(hasRsa: Boolean, hasEc: Boolean) =
        JSONObject()
            .put("rsa", hasRsa)
            .put("ec", hasEc)
            .put(
                "label",
                when {
                    hasRsa && hasEc -> "RSA+EC"
                    hasEc -> "EC-only"
                    hasRsa -> "RSA-only"
                    else -> "none"
                },
            )

    private fun validateKey(ke: Element, algorithm: String): JSONObject {
        val label = if (algorithm == "rsa") "RSA" else "EC"
        val privateNode = firstChild(ke, "PrivateKey") ?: error("$label: missing PrivateKey")
        val privatePem = privateNode.textContent?.trim().orEmpty()
        if (privatePem.isEmpty()) error("$label: empty PrivateKey")
        val privateKey = parsePrivateKey(privatePem)

        val certParent = firstChild(ke, "CertificateChain") ?: ke
        val certNodes = certParent.getElementsByTagName("Certificate")
        if (certNodes.length < 2) error("$label: expected at least 2 certificates, found ${certNodes.length}")
        val certs = ArrayList<X509Certificate>(certNodes.length)
        for (i in 0 until certNodes.length) {
            certs.add(parsePem(certNodes.item(i).textContent) ?: error("$label: certificate $i could not be parsed"))
        }

        val expectedPublic = if (algorithm == "rsa") "RSA" else "EC"
        if (!certs.first().publicKey.algorithm.equals(expectedPublic, ignoreCase = true)) {
            error("$label: leaf certificate public key is ${certs.first().publicKey.algorithm}")
        }
        if (!privateKeyMatches(privateKey, certs.first(), algorithm)) {
            error("$label: private key does not match the leaf certificate")
        }

        for (i in 0 until certs.size - 1) {
            if (certs[i].issuerX500Principal != certs[i + 1].subjectX500Principal) {
                error("$label: certificate chain linkage is broken at index $i")
            }
            try {
                certs[i].verify(certs[i + 1].publicKey)
            } catch (e: Exception) {
                error("$label: certificate signature verification failed at index $i")
            }
        }
        val top = certs.last()
        if (top.subjectX500Principal == top.issuerX500Principal) {
            try {
                top.verify(top.publicKey)
            } catch (e: Exception) {
                error("$label: self-signed root verification failed")
            }
        }

        return JSONObject()
            .put("algorithm", algorithm)
            .put("chainLength", certs.size)
            .put("privateKeyMatchesLeaf", true)
    }

    private fun parsePrivateKey(pem: String): PrivateKey {
        PEMParser(StringReader(pem)).use { parser ->
            val obj = parser.readObject() ?: error("empty private key PEM")
            val converter = JcaPEMKeyConverter().setProvider(BouncyCastleProvider())
            return when (obj) {
                // SEC1 EC PEM may not carry an encoded public-key half. Convert the embedded
                // PKCS#8 PrivateKeyInfo directly instead of requiring a complete PEMKeyPair.
                is PEMKeyPair -> converter.getPrivateKey(obj.privateKeyInfo)
                is PrivateKeyInfo -> converter.getPrivateKey(obj)
                else -> error("unsupported private key PEM object: ${obj.javaClass.simpleName}")
            }
        }
    }

    private fun privateKeyMatches(
        privateKey: PrivateKey,
        leaf: X509Certificate,
        algorithm: String,
    ): Boolean =
        try {
            val sigName = if (algorithm == "rsa") "SHA256withRSA" else "SHA256withECDSA"
            val probe = "TEESimulator-keybox-validation".toByteArray(Charsets.UTF_8)
            val signer = Signature.getInstance(sigName, BouncyCastleProvider.PROVIDER_NAME)
            signer.initSign(privateKey)
            signer.update(probe)
            val signature = signer.sign()
            val verifier = Signature.getInstance(sigName, BouncyCastleProvider.PROVIDER_NAME)
            verifier.initVerify(leaf.publicKey)
            verifier.update(probe)
            verifier.verify(signature)
        } catch (_: Exception) {
            false
        }

    private fun certJson(index: Int, cert: X509Certificate): JSONObject {
        val now = System.currentTimeMillis()
        val (keyAlgo, keySize) = keyInfo(cert)
        return JSONObject()
            .put("index", index)
            .put("subject", cert.subjectX500Principal.name)
            .put("issuer", cert.issuerX500Principal.name)
            .put("serial", cert.serialNumber.toString(16))
            .put("notBefore", cert.notBefore.time)
            .put("notAfter", cert.notAfter.time)
            .put("expired", cert.notAfter.time < now)
            .put("notYetValid", cert.notBefore.time > now)
            .put("sigAlg", cert.sigAlgName)
            .put("keyAlgorithm", keyAlgo)
            .put("keySize", keySize)
            .put("isCa", cert.basicConstraints >= 0)
            .put("selfSigned", cert.subjectX500Principal == cert.issuerX500Principal)
    }

    private fun keyInfo(cert: X509Certificate): Pair<String, Int> =
        when (val pk = cert.publicKey) {
            is RSAPublicKey -> "RSA" to pk.modulus.bitLength()
            is ECPublicKey -> "EC" to pk.params.curve.field.fieldSize
            else -> (pk.algorithm ?: "?") to 0
        }

    /** "ok" when each cert's issuer is the next cert's subject; "broken" otherwise. */
    private fun linkage(chain: List<X509Certificate>): String {
        if (chain.isEmpty()) return "empty"
        if (chain.size == 1) return "single"
        for (i in 0 until chain.size - 1) {
            if (chain[i].issuerX500Principal != chain[i + 1].subjectX500Principal) return "broken"
        }
        return "ok"
    }

    private fun parsePem(text: String): X509Certificate? =
        try {
            val body =
                text
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replace(Regex("\\s"), "")
            if (body.isEmpty()) null
            else
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode(body)))
                    as X509Certificate
        } catch (e: Exception) {
            null
        }

    /** A DocumentBuilder with DTD/external-entity processing off — it parses an untrusted file. */
    private fun newSafeBuilder() =
        DocumentBuilderFactory.newInstance()
            .apply {
                isNamespaceAware = false
                for (f in
                    listOf(
                        "http://apache.org/xml/features/disallow-doctype-decl" to true,
                        "http://xml.org/sax/features/external-general-entities" to false,
                        "http://xml.org/sax/features/external-parameter-entities" to false,
                    )) {
                    try {
                        setFeature(f.first, f.second)
                    } catch (_: Exception) {}
                }
                isExpandEntityReferences = false
            }
            .newDocumentBuilder()

    private fun firstChild(parent: Element, tag: String): Element? {
        val n = parent.getElementsByTagName(tag)
        return if (n.length > 0) n.item(0) as? Element else null
    }

    private fun fail(msg: String) = JSONObject().put("ok", false).put("error", msg)
}
