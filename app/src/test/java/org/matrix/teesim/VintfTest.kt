package org.matrix.teesim

import java.io.File
import kotlin.io.path.createTempDirectory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VintfTest {
    private fun fixture(name: String, xml: String): File {
        val dir = createTempDirectory("teesim-vintf-").toFile()
        return File(dir, name).apply { writeText(xml.trimIndent()) }
    }

    private fun source(
        file: File,
        partition: Vintf.Partition,
        apex: String? = null,
    ) = Vintf.ManifestSource(file, partition, apex)

    @Test
    fun vendorAndOdmOverrideKeepTeeAndStrongBoxIndependent() {
        val vendor =
            fixture(
                "vendor.xml",
                """
                <manifest version="1.0" type="device">
                  <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>2</version>
                    <interface>
                      <name>IKeyMintDevice</name>
                      <instance>default</instance>
                    </interface>
                  </hal>
                </manifest>
                """
            )
        val odm =
            fixture(
                "odm.xml",
                """
                <manifest version="1.0" type="device">
                  <hal format="aidl" override="true">
                    <name>android.hardware.security.keymint</name>
                    <version>3</version>
                    <interface>
                      <name>IKeyMintDevice</name>
                      <instance>default</instance>
                    </interface>
                  </hal>
                  <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>2</version>
                    <interface>
                      <name>IKeyMintDevice</name>
                      <instance>strongbox</instance>
                    </interface>
                  </hal>
                </manifest>
                """
            )

        val resolved =
            Vintf.resolveKeyMintDeclarations(
                listOf(
                    source(vendor, Vintf.Partition.VENDOR),
                    source(odm, Vintf.Partition.ODM),
                )
            )

        assertEquals(2, resolved.size)
        assertEquals(3, resolved["default"]?.version)
        assertEquals("odm", resolved["default"]?.partition)
        assertTrue(resolved["default"]?.overridden == true)
        assertEquals(2, resolved["strongbox"]?.version)
        assertEquals("odm", resolved["strongbox"]?.partition)
    }

    @Test
    fun emptyOverrideDisablesEarlierAidlHal() {
        val vendor =
            fixture(
                "vendor.xml",
                """
                <manifest version="1.0" type="device">
                  <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>2</version>
                    <interface>
                      <name>IKeyMintDevice</name>
                      <instance>default</instance>
                    </interface>
                  </hal>
                </manifest>
                """
            )
        val disable =
            fixture(
                "disable.xml",
                """
                <manifest version="1.0" type="device">
                  <hal format="aidl" override="true">
                    <name>android.hardware.security.keymint</name>
                    <version>3</version>
                  </hal>
                </manifest>
                """
            )

        val resolved =
            Vintf.resolveKeyMintDeclarations(
                listOf(
                    source(vendor, Vintf.Partition.VENDOR),
                    source(disable, Vintf.Partition.ODM),
                )
            )

        assertTrue(resolved.isEmpty())
    }

    @Test
    fun aidlWithoutVersionDefaultsToOne() {
        val file =
            fixture(
                "default-version.xml",
                """
                <manifest version="1.0" type="device">
                  <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <interface>
                      <name>IKeyMintDevice</name>
                      <instance>default</instance>
                    </interface>
                  </hal>
                </manifest>
                """
            )

        val resolved =
            Vintf.resolveKeyMintDeclarations(
                listOf(source(file, Vintf.Partition.VENDOR))
            )

        assertEquals(1, resolved["default"]?.version)
    }

    @Test
    fun frameworkManifestDoesNotParticipateInDeviceKeyMintResolution() {
        val file =
            fixture(
                "framework.xml",
                """
                <manifest version="1.0" type="framework">
                  <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>99</version>
                    <interface>
                      <name>IKeyMintDevice</name>
                      <instance>default</instance>
                    </interface>
                  </hal>
                </manifest>
                """
            )

        val resolved =
            Vintf.resolveKeyMintDeclarations(
                listOf(source(file, Vintf.Partition.SYSTEM))
            )

        assertTrue(resolved.isEmpty())
    }

    @Test
    fun apexSourcePreservesOriginEvidence() {
        val apex =
            fixture(
                "apex-keymint.xml",
                """
                <manifest version="1.0" type="device">
                  <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>4</version>
                    <interface>
                      <name>IKeyMintDevice</name>
                      <instance>strongbox</instance>
                    </interface>
                  </hal>
                </manifest>
                """
            )

        val resolved =
            Vintf.resolveKeyMintDeclarations(
                listOf(
                    source(
                        apex,
                        Vintf.Partition.ODM,
                        "com.oplus.hardware.keymint.strongbox",
                    )
                )
            )

        val strongbox = resolved["strongbox"]
        assertEquals(4, strongbox?.version)
        assertEquals("odm", strongbox?.partition)
        assertEquals("com.oplus.hardware.keymint.strongbox", strongbox?.apexModule)
    }

    @Test
    fun legacyKeymasterRangeUsesHighestSupportedAttestationVersion() {
        val file =
            fixture(
                "keymaster.xml",
                """
                <manifest version="1.0" type="device">
                  <hal format="hidl">
                    <name>android.hardware.keymaster</name>
                    <version>4.0-1</version>
                    <interface>
                      <name>IKeymasterDevice</name>
                      <instance>default</instance>
                    </interface>
                  </hal>
                </manifest>
                """
            )

        val resolved =
            Vintf.resolveKeymasterDeclarations(
                listOf(source(file, Vintf.Partition.VENDOR))
            )

        assertEquals(4, resolved["default"])
    }

    @Test
    fun skuSpecificManifestCandidatesComeBeforeGenericBase() {
        val vendor = Vintf.vendorManifestCandidates("CN")
        val odm = Vintf.odmManifestCandidates("sm8750")

        assertEquals("/vendor/etc/vintf/manifest_CN.xml", vendor.first())
        assertEquals("/vendor/etc/vintf/manifest.xml", vendor.last())
        assertEquals("/odm/etc/vintf/manifest_sm8750.xml", odm.first())
        assertTrue(odm.indexOf("/odm/etc/vintf/manifest.xml") < odm.indexOf("/odm/etc/manifest_sm8750.xml"))
    }

    @Test
    fun apexReadinessControlsNormalVsBootstrapPriority() {
        val ready = Vintf.apexInfoCandidates(true)
        val bootstrap = Vintf.apexInfoCandidates(false)

        assertEquals("/apex/apex-info-list.xml", ready.first().first)
        assertEquals("/apex", ready.first().second)
        assertEquals("/bootstrap-apex/apex-info-list.xml", bootstrap.first().first)
        assertEquals("/bootstrap-apex", bootstrap.first().second)
    }

    @Test
    fun oldApexInfoSchemaInfersVendorPartitionFromPreinstalledPath() {
        val file =
            fixture(
                "apex-info-list.xml",
                """
                <apex-info-list>
                  <apex-info
                    moduleName="com.vendor.keymint"
                    isActive="true"
                    preinstalledModulePath="/vendor/apex/com.vendor.keymint.apex" />
                  <apex-info
                    moduleName="com.system.other"
                    isActive="false"
                    preinstalledModulePath="/system/apex/com.system.other.apex" />
                </apex-info-list>
                """
            )

        val entries = Vintf.parseApexInfoList(file, "/apex")
        val vendor = entries.first { it.moduleName == "com.vendor.keymint" }

        assertTrue(vendor.active)
        assertEquals(Vintf.Partition.VENDOR, vendor.partition)
        assertEquals("/apex", vendor.mountRoot)
        assertFalse(entries.first { it.moduleName == "com.system.other" }.active)
    }

    @Test
    fun invalidMultipleAidlVersionsAreIgnored() {
        val file =
            fixture(
                "invalid.xml",
                """
                <manifest version="1.0" type="device">
                  <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>2</version>
                    <version>3</version>
                    <interface>
                      <name>IKeyMintDevice</name>
                      <instance>default</instance>
                    </interface>
                  </hal>
                </manifest>
                """
            )

        val resolved =
            Vintf.resolveKeyMintDeclarations(
                listOf(source(file, Vintf.Partition.VENDOR))
            )

        assertNull(resolved["default"])
    }
}
