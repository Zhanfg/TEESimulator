package org.matrix.teesim

/**
 * Pure VINTF merge core shared by the on-device resolver and host-side regression tests.
 *
 * Filesystem/property/APEX discovery stays in [Vintf]; this object only consumes sources in the
 * exact order Android would merge them. That keeps override/version/instance semantics testable on
 * the JVM without mocking Android's filesystem or Xml parser.
 */
internal object VintfMerge {
    data class Source(
        val path: String,
        val partition: String,
        val apexModule: String? = null,
    )

    data class AidlEntry(
        val override: Boolean,
        val versions: List<Int>,
        val instances: Set<String>,
    )

    data class HidlEntry(
        val override: Boolean,
        val versionsByInstance: Map<String, List<String>>,
    )

    data class AidlSource(val source: Source, val entries: List<AidlEntry>)

    data class HidlSource(val source: Source, val entries: List<HidlEntry>)

    data class Declaration(
        val instance: String,
        val version: Int,
        val source: String,
        val partition: String,
        val apexModule: String?,
        val overridden: Boolean,
    )

    /**
     * Merge AIDL KeyMint declarations in source order.
     *
     * AIDL HALs use a synthetic common major version in libvintf, so override=true replaces all
     * prior instances of the HAL. An empty override therefore disables the HAL completely.
     */
    fun mergeAidl(sources: List<AidlSource>): LinkedHashMap<String, Declaration> {
        val effective = LinkedHashMap<String, Declaration>()
        for (source in sources) {
            for (entry in source.entries) {
                if (entry.override) effective.clear()
                if (entry.instances.isEmpty()) continue
                val version = entry.versions.singleOrNull() ?: continue
                for (instance in entry.instances) {
                    effective[instance] =
                        Declaration(
                            instance = instance,
                            version = version,
                            source = source.source.path,
                            partition = source.source.partition,
                            apexModule = source.source.apexModule,
                            overridden = entry.override,
                        )
                }
            }
        }
        return effective
    }

    /**
     * Merge legacy HIDL Keymaster declarations in source order.
     *
     * Keymaster historically has one progressing service family, so an override replaces the prior
     * effective instance set. Version ranges are expanded before mapping to attestation versions.
     */
    fun mergeHidl(sources: List<HidlSource>): LinkedHashMap<String, Int> {
        val effective = LinkedHashMap<String, Int>()
        for (source in sources) {
            for (entry in source.entries) {
                if (entry.override) effective.clear()
                for ((instance, rawVersions) in entry.versionsByInstance) {
                    rawVersions
                        .flatMap(::expandHidlVersions)
                        .mapNotNull(::keymasterAttestationVersion)
                        .maxOrNull()
                        ?.let { effective[instance] = it }
                }
            }
        }
        return effective
    }

    fun keymasterAttestationVersion(dotted: String): Int? =
        when (dotted.trim()) {
            "2.0" -> 1
            "3.0" -> 2
            "4.0" -> 3
            "4.1" -> 4
            else -> null
        }

    fun expandHidlVersions(version: String): List<String> {
        val range = Regex("^([0-9]+)\\.([0-9]+)-([0-9]+)$").matchEntire(version.trim())
            ?: return listOf(version.trim())
        val major = range.groupValues[1]
        val first = range.groupValues[2].toInt()
        val last = range.groupValues[3].toInt()
        if (last < first) return emptyList()
        return (first..last).map { "$major.$it" }
    }
}
