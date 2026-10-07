package org.matrix.teesim

import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.spec.ECGenParameterSpec
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test

class KeyboxInspectorTest {
    companion object {
        @JvmStatic
        @BeforeClass
        fun installBc() {
            if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
        }
    }

    private data class Chain(
        val key: KeyPair,
        val leaf: java.security.cert.X509Certificate,
        val root: java.security.cert.X509Certificate,
    )

    private fun chain(kind: String, serialBase: Long): Chain {
        val gen =
            when (kind) {
                "rsa" -> KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
                else ->
                    KeyPairGenerator.getInstance("EC").apply {
                        initialize(ECGenParameterSpec("secp256r1"))
                    }
            }
        val rootKey = gen.generateKeyPair()
        val leafKey = gen.generateKeyPair()
        val sig = if (kind == "rsa") "SHA256withRSA" else "SHA256withECDSA"
        val now = System.currentTimeMillis()
        val notBefore = Date(now - 60_000)
        val notAfter = Date(now + 86_400_000)
        val rootName = X500Name("CN=TES Test Root $serialBase")
        val leafName = X500Name("CN=TES Test Leaf $serialBase")

        val rootHolder: X509CertificateHolder =
            JcaX509v3CertificateBuilder(
                    rootName,
                    BigInteger.valueOf(serialBase),
                    notBefore,
                    notAfter,
                    rootName,
                    rootKey.public,
                )
                .build(JcaContentSignerBuilder(sig).setProvider("BC").build(rootKey.private))
        val rootCert =
            JcaX509CertificateConverter().setProvider("BC").getCertificate(rootHolder)

        val leafHolder =
            JcaX509v3CertificateBuilder(
                    rootName,
                    BigInteger.valueOf(serialBase + 1),
                    notBefore,
                    notAfter,
                    leafName,
                    leafKey.public,
                )
                .build(JcaContentSignerBuilder(sig).setProvider("BC").build(rootKey.private))
        val leafCert =
            JcaX509CertificateConverter().setProvider("BC").getCertificate(leafHolder)
        return Chain(leafKey, leafCert, rootCert)
    }

    private fun pem(value: Any): String {
        val out = StringWriter()
        JcaPEMWriter(out).use { it.writeObject(value) }
        return out.toString()
    }

    private fun block(
        algorithm: String,
        chain: Chain,
        privateOverride: KeyPair? = null,
        rootOverride: java.security.cert.X509Certificate? = null,
    ): String =
        """
        <Key algorithm="$algorithm">
          <PrivateKey format="pem">${pem((privateOverride ?: chain.key).private)}</PrivateKey>
          <CertificateChain>
            <Certificate format="pem">${pem(chain.leaf)}</Certificate>
            <Certificate format="pem">${pem(rootOverride ?: chain.root)}</Certificate>
          </CertificateChain>
        </Key>
        """.trimIndent()

    private fun keybox(vararg blocks: String): String =
        """
        <AndroidAttestation>
          <Keybox DeviceID="test">
            ${blocks.joinToString("\n")}
          </Keybox>
        </AndroidAttestation>
        """.trimIndent()

    @Test
    fun ecOnlyKeyboxIsAccepted() {
        val result = KeyboxInspector.validateText(keybox(block("ecdsa", chain("ec", 100))))
        assertTrue(result.toString(), result.getBoolean("ok"))
        assertTrue(result.getJSONObject("capabilities").getBoolean("ec"))
        assertFalse(result.getJSONObject("capabilities").getBoolean("rsa"))
    }

    @Test
    fun rsaOnlyKeyboxIsAccepted() {
        val result = KeyboxInspector.validateText(keybox(block("rsa", chain("rsa", 200))))
        assertTrue(result.toString(), result.getBoolean("ok"))
        assertTrue(result.getJSONObject("capabilities").getBoolean("rsa"))
        assertFalse(result.getJSONObject("capabilities").getBoolean("ec"))
    }

    @Test
    fun dualAlgorithmKeyboxIsAccepted() {
        val result =
            KeyboxInspector.validateText(
                keybox(block("rsa", chain("rsa", 300)), block("ecdsa", chain("ec", 400)))
            )
        assertTrue(result.toString(), result.getBoolean("ok"))
        assertTrue(result.getJSONObject("capabilities").getBoolean("rsa"))
        assertTrue(result.getJSONObject("capabilities").getBoolean("ec"))
    }

    @Test
    fun mismatchedPrivateKeyIsRejected() {
        val good = chain("ec", 500)
        val other = chain("ec", 600)
        val result =
            KeyboxInspector.validateText(
                keybox(block("ecdsa", good, privateOverride = other.key))
            )
        assertFalse(result.toString(), result.getBoolean("ok"))
        assertTrue(result.getString("error").contains("does not match"))
    }

    @Test
    fun brokenCertificateChainIsRejected() {
        val good = chain("rsa", 700)
        val otherRoot = chain("rsa", 800).root
        val result =
            KeyboxInspector.validateText(keybox(block("rsa", good, rootOverride = otherRoot)))
        assertFalse(result.toString(), result.getBoolean("ok"))
        assertTrue(
            result.getString("error").contains("linkage") ||
                result.getString("error").contains("signature")
        )
    }

    @Test
    fun duplicateAlgorithmIsRejected() {
        val result =
            KeyboxInspector.validateText(
                keybox(
                    block("ecdsa", chain("ec", 900)),
                    block("ecdsa", chain("ec", 1000)),
                )
            )
        assertFalse(result.toString(), result.getBoolean("ok"))
        assertTrue(result.getString("error").contains("duplicate"))
    }

    @Test
    fun unsupportedOnlyKeyboxIsRejected() {
        val result = KeyboxInspector.validateText(keybox("<Key algorithm=\"dsa\"/>"))
        assertFalse(result.toString(), result.getBoolean("ok"))
    }
}
