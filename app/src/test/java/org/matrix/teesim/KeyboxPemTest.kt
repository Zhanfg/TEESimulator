package org.matrix.teesim

import java.io.StringReader
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.PEMParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyboxPemTest {
    @Test
    fun indentedEcSec1MarkersAreNormalizedWithoutChangingBase64() {
        val raw = "\n                -----BEGIN EC PRIVATE KEY-----\r\n" +
            "                AQIDBA==\r\n                -----END EC PRIVATE KEY-----\n"
        assertEquals(
            "-----BEGIN EC PRIVATE KEY-----\nAQIDBA==\n-----END EC PRIVATE KEY-----\n",
            normalizeKeyboxPem(raw),
        )
    }

    @Test
    fun indentedPkcs8IsAcceptedByRealBouncyCastleParser() {
        val kp = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val base64 = Base64.getMimeEncoder(64, byteArrayOf('\n'.code.toByte()))
            .encodeToString(kp.private.encoded)
        val embedded = "    -----BEGIN PRIVATE KEY-----\n" +
            base64.lines().joinToString("\r\n") { "        $it" } +
            "\n    -----END PRIVATE KEY-----"
        val canonical = normalizeKeyboxPem(embedded)
        PEMParser(StringReader(canonical)).use { parser ->
            val obj = parser.readObject()
            assertNotNull(obj)
            assertTrue(obj is PrivateKeyInfo)
        }
    }

    @Test
    fun badFooterAndMultipleBlocksStillFailClosed() {
        val invalids = listOf(
            "-----BEGIN EC PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----\nAQID\n-----BEGIN CERTIFICATE-----\n-----END EC PRIVATE KEY-----",
            "  ",
        )
        for (invalid in invalids) {
            var rejected = false
            try {
                normalizeKeyboxPem(invalid)
            } catch (_: IllegalStateException) {
                rejected = true
            }
            assertTrue("malformed PEM must be rejected", rejected)
        }
    }
}
