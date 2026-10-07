package org.matrix.teesim

import java.io.ByteArrayOutputStream

/**
 * Re-roots pre-existing keys' attestation on a config push. A key generated before its app was
 * covered (or under a previous keybox) still carries the real hardware attestation — an unlocked
 * root of trust rooted in the device's real attestation key. For each target app, every stored key
 * that carries such a leaf is re-signed under its profile's keybox — the same patch the router
 * applies to a freshly generated key — and written back. The write-back mirrors the delete path: it
 * asks keystore2 as the key's OWNER first ([Keystore2Service.updateSubcomponentAsUid], which
 * seteuid's to the owner in a child), and a key keystore2 refuses falls back to a direct database
 * write ([KeystoreDb.updateSubcomponents]). The key blob is never touched, so the real hardware key
 * keeps working; only the certificate the app reads changes.
 *
 * Idempotent and record-less: it re-scans the live keystore each run and re-signs whatever it
 * finds, so a re-run, a keybox swap, or a newly installed app all converge on the next push.
 */
object ReAttest {

    /**
     * Delete compatibility-profile apps' existing foreign attestation keys so those modes can
     * regenerate a software-owned key, and return whether keystore2 was restarted as a result.
     *
     * Strict hardware profiles are deliberately excluded. Their ATTEST_KEY private half must remain
     * in the genuine TEE/StrongBox; [run] re-roots only the stored public certificate under the
     * profile keybox, preserving the hardware key and delegated signing graph.
     *
     * keystore2 only lets a key's OWNER delete it (KeyPerm::Delete, AOSP service.rs), so the daemon
     * can't remove another app's key through the API — [KeystoreDb.deleteTargetAttestKeys] falls
     * back to a direct database delete, which removes the row but does NOT evict keystore2's
     * in-memory cache, so the app would keep using the cached key. We therefore restart keystore2
     * after a purge so it reloads from the (now smaller) database; the injector re-injects on the
     * new pid.
     */
    fun purgeTargetAttestKeys(config: ConfigStore.Config): Boolean {
        val uidToProfile = Scope.uidToProfile(config)
        if (uidToProfile.isEmpty()) return false

        val modeByProfile = config.profiles.associate { it.id to it.mode }
        val compatibilityUids =
            uidToProfile
                .filterValues { profileId -> modeByProfile[profileId] != "hardware" }
                .keys
        val hardwareUids =
            uidToProfile
                .filterValues { profileId -> modeByProfile[profileId] == "hardware" }
                .keys

        var needRestart = 0

        // Compatibility profiles still need to remove genuine/foreign ATTEST_KEYs so their next
        // graph is rebuilt under the software TA they intentionally use.
        if (compatibilityUids.isNotEmpty()) {
            needRestart += KeystoreDb.deleteTargetAttestKeys(compatibilityUids)
        }

        // Strict hardware profiles do the inverse migration: preserve genuine TEE/StrongBox
        // ATTEST_KEYs, but remove only old TES-marked software parents left from a previous
        // generation/patch configuration. This is safe because an attestation key is a signing
        // parent; we do NOT delete ordinary business keys, which may protect application data.
        if (hardwareUids.isNotEmpty()) {
            needRestart += KeystoreDb.deleteTargetSyntheticAttestKeys(hardwareUids)
        }

        if (needRestart == 0) {
            SystemLogger.info(
                "ReAttest: ATTEST_KEY ownership already matches all profile modes; no keystore2 " +
                    "restart required"
            )
            return false
        }

        SystemLogger.info(
            "ReAttest: $needRestart ATTEST_KEY migration(s) required direct database deletion; " +
                "restarting keystore2 to evict stale cached parents"
        )
        return restartKeystore2()
    }

    /**
     * Ask init to restart keystore2 so it reloads keys from the database (dropping any cached copy
     * of a key we deleted directly). Best-effort: returns true if the restart command was issued.
     */
    private fun restartKeystore2(): Boolean {
        return try {
            val p =
                ProcessBuilder("setprop", "ctl.restart", "keystore2")
                    .redirectErrorStream(true)
                    .start()
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            SystemLogger.info(
                "ReAttest: requested keystore2 restart (exit ${p.exitValue()}${if (out.isEmpty()) "" else ", $out"})"
            )
            true
        } catch (e: Throwable) {
            SystemLogger.warning(
                "ReAttest: could not restart keystore2; the purge will take effect on next boot",
                e,
            )
            false
        }
    }

    /**
     * Re-attest every eligible pre-existing key of [config]'s target apps against the live
     * profiles.
     */
    fun run(config: ConfigStore.Config) {
        // uid -> the profile whose keybox should sign that app's keys (one profile per package),
        // resolved and logged centrally by Scope so raw uid:N tokens and auto-include are covered.
        val uidToProfile = Scope.uidToProfile(config)
        if (uidToProfile.isEmpty()) return
        val modeByProfile = config.profiles.associate { it.id to it.mode }
        val hardwareUidToProfile =
            uidToProfile.filterValues { profileId -> modeByProfile[profileId] == "hardware" }

        // 1) Ordinary hardware-backed app keys: patch their Android KeyDescription and re-root the
        // leaf exactly as before. This changes only stored certificates, never the KeyMint key blob.
        val keys = KeystoreDb.attestedKeys(uidToProfile.keys)
        SystemLogger.info(
            "ReAttest: ${keys.size} pre-existing target key(s) to re-root across " +
                "${uidToProfile.size} uid(s)"
        )

        var done = 0
        val dbFallback = ArrayList<KeystoreDb.CertUpdate>()
        for (key in keys) {
            val profileId = uidToProfile[key.uid] ?: continue
            val chain =
                Control.resign(profileId, key.leaf)
                    ?: run {
                        SystemLogger.warning(
                            "ReAttest: key id=${key.id} uid=${key.uid} — resign failed; skipping"
                        )
                        continue
                    }
            if (chain.isEmpty()) continue
            val leaf = chain[0]
            val rest = concatFrom(chain, 1)
            if (Keystore2Service.updateSubcomponentAsUid(key.id, key.uid, leaf, rest) == 0) {
                done++
                SystemLogger.info(
                    "ReAttest: key id=${key.id} uid=${key.uid} profile=$profileId re-rooted " +
                        "(${chain.size}-cert chain)"
                )
            } else {
                dbFallback.add(KeystoreDb.CertUpdate(key.id, leaf, rest))
            }
        }
        if (dbFallback.isNotEmpty()) {
            SystemLogger.warning(
                "ReAttest: keystore2 refused the owner update for ${dbFallback.size} key(s); " +
                    "falling back to a direct database write"
            )
            done += KeystoreDb.updateSubcomponents(uidToProfile.keys, dbFallback)
        }
        SystemLogger.info(
            "ReAttest: re-rooted $done of ${keys.size} pre-existing target key(s) to the keybox"
        )

        // 2) Assigned RKP/attestation-key pool entries for strict hardware profiles. Their private
        // key blob is the hardware asset that later signs business-key leaves, so it must remain
        // byte-for-byte untouched. Reissue only the certificate for the SAME public key under the
        // profile keybox. This turns the delegated chain into:
        // business leaf <- real hardware ATTEST_KEY <- TES keybox.
        if (hardwareUidToProfile.isEmpty()) return
        val rkpKeys = KeystoreDb.rkpAttestationKeys(hardwareUidToProfile.keys)
        if (rkpKeys.isEmpty()) {
            SystemLogger.verbose(
                "ReAttest: no database-backed RKP attestation key assigned to strict hardware targets"
            )
            return
        }

        val rkpUpdates = ArrayList<KeystoreDb.CertUpdate>()
        for (key in rkpKeys) {
            val profileId = hardwareUidToProfile[key.uid] ?: continue
            val chain =
                Control.reissue(profileId, key.leaf)
                    ?: run {
                        SystemLogger.warning(
                            "ReAttest: RKP key id=${key.id} uid=${key.uid} — certificate reissue " +
                                "failed; hardware key blob left untouched"
                        )
                        continue
                    }
            if (chain.isEmpty()) continue
            rkpUpdates.add(KeystoreDb.CertUpdate(key.id, chain[0], concatFrom(chain, 1)))
        }
        val rkpDone =
            if (rkpUpdates.isEmpty()) 0
            else KeystoreDb.updateRkpSubcomponents(hardwareUidToProfile.keys, rkpUpdates)
        SystemLogger.info(
            "ReAttest: re-rooted $rkpDone of ${rkpKeys.size} assigned hardware RKP/ATTEST_KEY " +
                "certificate chain(s); private key blobs were not modified"
        )
    }

    /**
     * DER concatenation of [certs] from index [from] onward (empty when there are no further
     * certs).
     */
    private fun concatFrom(certs: List<ByteArray>, from: Int): ByteArray {
        val bos = ByteArrayOutputStream()
        for (i in from until certs.size) bos.write(certs[i])
        return bos.toByteArray()
    }
}
