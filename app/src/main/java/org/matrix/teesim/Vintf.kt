package org.matrix.teesim

import android.util.Xml
import java.io.File
import org.xmlpull.v1.XmlPullParser

/**
 * Resolve the device's KeyMint/Keymaster declaration with VINTF merge semantics close to libvintf.
 *
 * The old implementation scanned every vendor/odm/system manifest independently and returned the
 * highest version it happened to see. That is not how Android assembles a device manifest: vendor
 * and ODM fragments are merged in order, override="true" can replace or disable an earlier HAL,
 * AIDL defaults to version 1 when <version> is absent, and active vendor/ODM APEXes may contribute
 * manifest fragments. Getting this wrong is especially visible on OPlus devices where TEE and
 * StrongBox can come from different vendor components.
 */
object Vintf {

    private const val KEYMINT_HAL = "android.hardware.security.keymint"
    private const val KEYMINT_IFACE = "IKeyMintDevice"
    private const val KEYMASTER_HAL = "android.hardware.keymaster"
    private const val KEYMASTER_IFACE = "IKeymasterDevice"

    private val HIDL_FQNAME = Regex("^@([0-9]+(?:\\.[0-9]+)?)::([^/]+)/(.+)$")
    private val HIDL_RANGE = Regex("^([0-9]+)\\.([0-9]+)-([0-9]+)$")

    private enum class Partition {
        VENDOR,
        ODM,
        SYSTEM,
        SYSTEM_EXT,
        PRODUCT,
        UNKNOWN,
    }

    private data class ManifestSource(
        val file: File,
        val partition: Partition,
        val apexModule: String? = null,
    )

    private data class ApexInfo(
        val moduleName: String,
        val active: Boolean,
        val partition: Partition,
        val mountRoot: String,
    )

    private data class ParsedAidlHal(
        val override: Boolean,
        val versions: List<Int>,
        val instances: Set<String>,
    )

    private data class ParsedHidlHal(
        val override: Boolean,
        val versionsByInstance: Map<String, List<String>>,
    )

    /**
     * The effective declaration after vendor/ODM/APEX merge. Exposed for diagnostics so a future
     * hardware-profile resolver can distinguish "strongbox from ODM APEX" from a name heuristic.
     */
    data class KeyMintDeclaration(
        val instance: String,
        val version: Int,
        val source: String,
        val partition: String,
        val apexModule: String?,
        val overridden: Boolean,
    )

    enum class ConstraintKind {
        EXACT,
        CEILING,
    }

    data class AttestationConstraint(val version: Int, val kind: ConstraintKind) {
        fun violatedBy(current: Int): Boolean =
            when (kind) {
                ConstraintKind.EXACT -> current != version
                ConstraintKind.CEILING -> current > version
            }
    }

    private val declarationCache = HashMap<String, KeyMintDeclaration?>()
    private val keymasterCache = HashMap<String, Int?>()
    private val constraintCache = HashMap<String, AttestationConstraint?>()
    private var sourcesCache: List<ManifestSource>? = null

    @Synchronized
    fun attestationVersionConstraint(instance: String = "default"): AttestationConstraint? {
        if (constraintCache.containsKey(instance)) return constraintCache[instance]
        val c =
            keyMintDeclaration(instance)?.let {
                AttestationConstraint(it.version * 100, ConstraintKind.CEILING)
            }
                ?: keymasterHalAttestationVersion(instance)?.let {
                    AttestationConstraint(it, ConstraintKind.EXACT)
                }
        constraintCache[instance] = c
        SystemLogger.info(
            "Vintf: attestation-version constraint for '$instance' = " +
                "${c?.version ?: "unknown"} (${c?.kind ?: "unknown"})"
        )
        return c
    }

    @Synchronized
    fun keyMintHalVersion(instance: String = "default"): Int? = keyMintDeclaration(instance)?.version

    @Synchronized
    fun keyMintDeclaration(instance: String = "default"): KeyMintDeclaration? {
        if (declarationCache.containsKey(instance)) return declarationCache[instance]
        val declaration =
            runCatching { resolveKeyMintDeclarations()[instance] }
                .getOrElse {
                    SystemLogger.info(
                        "Vintf: KeyMint manifest resolution failed: " +
                            "${it.javaClass.simpleName}: ${it.message}"
                    )
                    null
                }
        declarationCache[instance] = declaration
        if (declaration == null) {
            SystemLogger.info("Vintf: effective KeyMint declaration '$instance' = unknown")
        } else {
            SystemLogger.info(
                "Vintf: effective KeyMint '$instance' @${declaration.version} from " +
                    "${declaration.partition}:${declaration.source}" +
                    (declaration.apexModule?.let { " apex=$it" } ?: "")
            )
        }
        return declaration
    }

    /**
     * Return all effective KeyMint instances. This is deliberately instance-centric rather than
     * "max version": default and strongbox are independent services and may have different versions.
     */
    @Synchronized
    fun keyMintDeclarations(): Map<String, KeyMintDeclaration> = resolveKeyMintDeclarations().toMap()

    @Synchronized
    fun keymasterHalAttestationVersion(instance: String = "default"): Int? {
        if (keymasterCache.containsKey(instance)) return keymasterCache[instance]
        val value =
            runCatching { resolveKeymasterDeclarations()[instance] }
                .getOrElse {
                    SystemLogger.info(
                        "Vintf: Keymaster manifest resolution failed: " +
                            "${it.javaClass.simpleName}: ${it.message}"
                    )
                    null
                }
        keymasterCache[instance] = value
        SystemLogger.info(
            "Vintf: effective Keymaster attestationVersion for '$instance' = ${value ?: "unknown"}"
        )
        return value
    }

    private fun resolveKeyMintDeclarations(): LinkedHashMap<String, KeyMintDeclaration> {
        val effective = LinkedHashMap<String, KeyMintDeclaration>()
        for (source in deviceManifestSources()) {
            val entries =
                runCatching { parseAidlKeyMint(source.file) }
                    .getOrElse {
                        SystemLogger.info(
                            "Vintf: ignoring unreadable manifest ${source.file}: " +
                                "${it.javaClass.simpleName}: ${it.message}"
                        )
                        emptyList()
                    }
            for (entry in entries) {
                // libvintf uses a synthetic common major version for AIDL. An override therefore
                // replaces the prior declarations of this AIDL HAL; an empty override disables it.
                if (entry.override) effective.clear()
                if (entry.instances.isEmpty()) continue

                val version = entry.versions.singleOrNull() ?: continue
                for (instance in entry.instances) {
                    effective[instance] =
                        KeyMintDeclaration(
                            instance = instance,
                            version = version,
                            source = source.file.absolutePath,
                            partition = source.partition.name.lowercase(),
                            apexModule = source.apexModule,
                            overridden = entry.override,
                        )
                }
            }
        }
        return effective
    }

    private fun resolveKeymasterDeclarations(): LinkedHashMap<String, Int> {
        val effective = LinkedHashMap<String, Int>()
        for (source in deviceManifestSources()) {
            val entries =
                runCatching { parseHidlKeymaster(source.file) }
                    .getOrElse { emptyList() }
            for (entry in entries) {
                // HIDL override is technically scoped by major version. For Keymaster's historical
                // one-service progression (2.x/3.x/4.x), replacing the package's effective instance
                // is the behavior that matches real device assembly and avoids stale vendor entries.
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

    /**
     * Device-manifest assembly order. KeyMint is a device HAL, so framework manifests under
     * system/system_ext/product must not be mixed into this resolution.
     */
    private fun deviceManifestSources(): List<ManifestSource> {
        sourcesCache?.let { return it }

        val out = ArrayList<ManifestSource>()
        val seen = HashSet<String>()

        fun add(file: File, partition: Partition, apex: String? = null) {
            if (!file.isFile) return
            val key = runCatching { file.canonicalPath }.getOrElse { file.absolutePath }
            if (seen.add(key)) out.add(ManifestSource(file, partition, apex))
        }

        fun addFragments(dir: File, partition: Partition, apex: String? = null) {
            dir.listFiles { f -> f.isFile && f.name.endsWith(".xml", true) }
                ?.sortedBy { it.name }
                ?.forEach { add(it, partition, apex) }
        }

        // Modern vendor manifest; only use the pre-Treble fallback if the modern base is absent.
        val vendorBase = File("/vendor/etc/vintf/manifest.xml")
        if (vendorBase.isFile) add(vendorBase, Partition.VENDOR)
        else add(File("/vendor/manifest.xml"), Partition.VENDOR)
        addFragments(File("/vendor/etc/vintf/manifest"), Partition.VENDOR)
        addApexSources(out, seen, Partition.VENDOR)

        // ODM overlays vendor and is intentionally processed afterwards.
        val odmBase = File("/odm/etc/vintf/manifest.xml")
        if (odmBase.isFile) add(odmBase, Partition.ODM)
        else add(File("/odm/manifest.xml"), Partition.ODM)
        addFragments(File("/odm/etc/vintf/manifest"), Partition.ODM)
        addApexSources(out, seen, Partition.ODM)

        sourcesCache = out
        SystemLogger.info(
            "Vintf: assembled ${out.size} device-manifest source(s): " +
                out.joinToString { "${it.partition.name.lowercase()}:${it.file.absolutePath}" }
        )
        return out
    }

    private fun addApexSources(
        out: MutableList<ManifestSource>,
        seen: MutableSet<String>,
        wantedPartition: Partition,
    ) {
        fun add(file: File, partition: Partition, module: String) {
            if (!file.isFile) return
            val key = runCatching { file.canonicalPath }.getOrElse { file.absolutePath }
            if (seen.add(key)) out.add(ManifestSource(file, partition, module))
        }

        for (apex in activeApexes()) {
            if (!apex.active || apex.partition != wantedPartition) continue
            val vintf = File("${apex.mountRoot}/${apex.moduleName}/etc/vintf")
            add(File(vintf, "manifest.xml"), wantedPartition, apex.moduleName)
            vintf.listFiles { f -> f.isFile && f.name.endsWith(".xml", true) }
                ?.sortedBy { it.name }
                ?.forEach { add(it, wantedPartition, apex.moduleName) }
            File(vintf, "manifest")
                .listFiles { f -> f.isFile && f.name.endsWith(".xml", true) }
                ?.sortedBy { it.name }
                ?.forEach { add(it, wantedPartition, apex.moduleName) }
        }
    }

    private fun activeApexes(): List<ApexInfo> {
        val candidates =
            listOf(
                File("/apex/apex-info-list.xml") to "/apex",
                File("/bootstrap-apex/apex-info-list.xml") to "/bootstrap-apex",
            )
        for ((file, root) in candidates) {
            if (!file.isFile) continue
            return runCatching { parseApexInfoList(file, root) }
                .getOrElse {
                    SystemLogger.info(
                        "Vintf: failed parsing ${file.absolutePath}: " +
                            "${it.javaClass.simpleName}: ${it.message}"
                    )
                    emptyList()
                }
        }
        return emptyList()
    }

    private fun parseApexInfoList(file: File, mountRoot: String): List<ApexInfo> {
        val out = ArrayList<ApexInfo>()
        file.inputStream().use { input ->
            val parser = Xml.newPullParser()
            parser.setInput(input, null)
            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                if (event == XmlPullParser.START_TAG && parser.name == "apex-info") {
                    val module = parser.getAttributeValue(null, "moduleName").orEmpty()
                    val active = parser.getAttributeValue(null, "isActive") == "true"
                    val partition =
                        when (parser.getAttributeValue(null, "partition")?.uppercase()) {
                            "VENDOR" -> Partition.VENDOR
                            "ODM" -> Partition.ODM
                            "SYSTEM" -> Partition.SYSTEM
                            "SYSTEM_EXT" -> Partition.SYSTEM_EXT
                            "PRODUCT" -> Partition.PRODUCT
                            else -> Partition.UNKNOWN
                        }
                    if (module.isNotEmpty()) out.add(ApexInfo(module, active, partition, mountRoot))
                }
                event = parser.next()
            }
        }
        return out
    }

    private fun parseAidlKeyMint(file: File): List<ParsedAidlHal> {
        val result = ArrayList<ParsedAidlHal>()
        file.inputStream().use { input ->
            val parser = Xml.newPullParser()
            parser.setInput(input, null)

            var manifestType: String? = null
            var inHal = false
            var aidl = false
            var override = false
            var halName: String? = null
            val versions = ArrayList<Int>()
            val instances = LinkedHashSet<String>()
            var ifaceName: String? = null

            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                if (event == XmlPullParser.START_TAG) {
                    val depth = parser.depth
                    when (parser.name) {
                        "manifest" -> manifestType = parser.getAttributeValue(null, "type")
                        "hal" -> {
                            inHal = true
                            aidl = "aidl".equals(parser.getAttributeValue(null, "format"), true)
                            override = "true".equals(parser.getAttributeValue(null, "override"), true)
                            halName = null
                            versions.clear()
                            instances.clear()
                            ifaceName = null
                        }
                        "interface" -> if (inHal) ifaceName = null
                        "name" ->
                            if (inHal) {
                                val text = readText(parser)
                                if (depth <= 3) halName = halName ?: text else ifaceName = text
                            }
                        "version" ->
                            if (inHal && depth <= 3) {
                                val raw = readText(parser)
                                raw.toIntOrNull()?.let(versions::add)
                                    ?: throw IllegalArgumentException(
                                        "invalid AIDL VINTF version '$raw' in ${file.absolutePath}"
                                    )
                            }
                        "instance" ->
                            if (inHal && ifaceName == KEYMINT_IFACE) {
                                val instance = readText(parser)
                                if (instance.isNotEmpty()) instances.add(instance)
                            }
                        "fqname" ->
                            if (inHal) {
                                val fq = readText(parser)
                                val iface = fq.substringBefore('/')
                                val instance = fq.substringAfter('/', "")
                                if (iface == KEYMINT_IFACE && instance.isNotEmpty()) {
                                    instances.add(instance)
                                }
                            }
                    }
                } else if (event == XmlPullParser.END_TAG && parser.name == "hal") {
                    if (
                        inHal &&
                            aidl &&
                            halName == KEYMINT_HAL &&
                            !manifestType.equals("framework", true)
                    ) {
                        val normalizedVersions =
                            when {
                                versions.isEmpty() -> listOf(1) // libvintf default AIDL version
                                versions.distinct().size == 1 -> listOf(versions.first())
                                else -> {
                                    SystemLogger.info(
                                        "Vintf: invalid KeyMint AIDL declaration with multiple " +
                                            "versions in ${file.absolutePath}; ignoring block"
                                    )
                                    emptyList()
                                }
                            }
                        if (normalizedVersions.isNotEmpty()) {
                            result.add(
                                ParsedAidlHal(
                                    override = override,
                                    versions = normalizedVersions,
                                    instances = instances.toSet(),
                                )
                            )
                        }
                    }
                    inHal = false
                }
                event = parser.next()
            }
        }
        return result
    }

    private fun parseHidlKeymaster(file: File): List<ParsedHidlHal> {
        val result = ArrayList<ParsedHidlHal>()
        file.inputStream().use { input ->
            val parser = Xml.newPullParser()
            parser.setInput(input, null)

            var manifestType: String? = null
            var inHal = false
            var hidl = false
            var override = false
            var halName: String? = null
            val versions = ArrayList<String>()
            val fqnames = ArrayList<String>()
            var ifaceName: String? = null
            val interfaceInstances = LinkedHashSet<String>()

            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                if (event == XmlPullParser.START_TAG) {
                    val depth = parser.depth
                    when (parser.name) {
                        "manifest" -> manifestType = parser.getAttributeValue(null, "type")
                        "hal" -> {
                            inHal = true
                            hidl = "hidl".equals(parser.getAttributeValue(null, "format"), true)
                            override = "true".equals(parser.getAttributeValue(null, "override"), true)
                            halName = null
                            versions.clear()
                            fqnames.clear()
                            ifaceName = null
                            interfaceInstances.clear()
                        }
                        "interface" -> if (inHal) ifaceName = null
                        "name" ->
                            if (inHal) {
                                val text = readText(parser)
                                if (depth <= 3) halName = halName ?: text else ifaceName = text
                            }
                        "version" ->
                            if (inHal && depth <= 3) {
                                readText(parser).takeIf { it.isNotEmpty() }?.let(versions::add)
                            }
                        "instance" ->
                            if (inHal && ifaceName == KEYMASTER_IFACE) {
                                readText(parser)
                                    .takeIf { it.isNotEmpty() }
                                    ?.let(interfaceInstances::add)
                            }
                        "fqname" ->
                            if (inHal) {
                                readText(parser).takeIf { it.isNotEmpty() }?.let(fqnames::add)
                            }
                    }
                } else if (event == XmlPullParser.END_TAG && parser.name == "hal") {
                    if (
                        inHal &&
                            hidl &&
                            halName == KEYMASTER_HAL &&
                            !manifestType.equals("framework", true)
                    ) {
                        val byInstance = LinkedHashMap<String, MutableList<String>>()
                        for (instance in interfaceInstances) {
                            byInstance.getOrPut(instance) { ArrayList() }.addAll(versions)
                        }
                        for (fq in fqnames) {
                            val m = HIDL_FQNAME.matchEntire(fq.trim()) ?: continue
                            val (version, iface, instance) = m.destructured
                            if (iface == KEYMASTER_IFACE) {
                                byInstance.getOrPut(instance) { ArrayList() }.add(version)
                            }
                        }
                        result.add(
                            ParsedHidlHal(
                                override = override,
                                versionsByInstance = byInstance.mapValues { it.value.toList() },
                            )
                        )
                    }
                    inHal = false
                }
                event = parser.next()
            }
        }
        return result
    }

    private fun keymasterAttestationVersion(dotted: String): Int? =
        when (dotted.trim()) {
            "2.0" -> 1
            "3.0" -> 2
            "4.0" -> 3
            "4.1" -> 4
            else -> null
        }

    private fun expandHidlVersions(version: String): List<String> {
        val m = HIDL_RANGE.matchEntire(version.trim()) ?: return listOf(version.trim())
        val major = m.groupValues[1]
        val first = m.groupValues[2].toInt()
        val last = m.groupValues[3].toInt()
        if (last < first) return emptyList()
        return (first..last).map { "$major.$it" }
    }

    private fun readText(parser: XmlPullParser): String =
        if (parser.next() == XmlPullParser.TEXT) parser.text?.trim().orEmpty() else ""
}
