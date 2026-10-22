package org.matrix.teesim

/**
 * Keybox XML frequently indents every line of its embedded private-key PEM.
 * BouncyCastle's PEM footer scanner is stricter than the XML format permits.
 *
 * Remove only surrounding whitespace from each line (including CRLF and BOM).
 * Never decode, regenerate, truncate or otherwise alter the private-key bytes.
 * Reject an absent/mismatched footer or nested PEM markers rather than silently
 * accepting malformed private-key material.
 */
internal fun normalizeKeyboxPem(pem: String): String {
    val lines = pem.lineSequence()
        .map { it.trim().removePrefix("\uFEFF").trim() }
        .filter { it.isNotEmpty() }
        .toList()
    val begin = lines.firstOrNull() ?: error("PEM 私钥不能为空")
    if (!begin.startsWith("-----BEGIN ") || !begin.endsWith("-----")) {
        error("PEM 私钥缺少合法的 BEGIN 标记")
    }
    val end = begin.replaceFirst("-----BEGIN ", "-----END ")
    if (lines.last() != end) {
        error("PEM 私钥结束标记缺失或不匹配，应为 $end")
    }
    if (lines.size < 3 || lines.subList(1, lines.size - 1).any { it.startsWith("-----") }) {
        error("PEM 私钥数据为空或包含多个 PEM 区块")
    }
    return lines.joinToString("\n", postfix = "\n")
}
