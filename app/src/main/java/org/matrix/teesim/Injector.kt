package org.matrix.teesim

import android.os.Build
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Finds the keystore daemon and drives the packaged `inject` binary to load the right interceptor
 * into it: `inject <pid> <lib.so> entry`. On Android 12+ the target is keystore2 with
 * libteesim_keymint.so; on 10/11 it is keystore with libteesim_keystore.so. Re-injects whenever the
 * daemon restarts (new pid).
 */
class Injector(private val moduleDir: File) {

    private val api = Build.VERSION.SDK_INT
    private val procName = if (api >= 31) "keystore2" else "keystore"
    private val libName = if (api >= 31) "libteesim_keymint.so" else "libteesim_keystore.so"

    private val abi: String =
        Build.SUPPORTED_ABIS?.firstOrNull() ?: DeviceProps.prop("ro.product.cpu.abi", "arm64-v8a")

    private val injectBin = File(moduleDir, "$abi/inject")
    private val libFile = File(moduleDir, "$abi/$libName")

    @Volatile private var running = false
    @Volatile private var lastPid = -1

    fun start() {
        if (running) return
        // A missing or non-executable injector cannot recover by scanning /proc forever.
        // Fail main startup explicitly so the bounded shell supervisor can retry when the
        // module files are actually available. No KeyMint state or key data is modified.
        if (!injectBin.isFile || !libFile.isFile) {
            throw IllegalStateException(
                "Injector artifacts unavailable for ABI $abi: inject=${injectBin.isFile} " +
                    "lib=${libFile.isFile} (module=${moduleDir.absolutePath})"
            )
        }
        if (!injectBin.canExecute() && !injectBin.setExecutable(true, false)) {
            throw IllegalStateException("Injector binary is not executable for ABI $abi")
        }
        running = true
        Thread({ loop() }, "teesim-injector").apply {
            isDaemon = true
            start()
        }
    }

    private fun loop() {
        SystemLogger.info("Injector: watching $procName (abi=$abi lib=$libName)")
        var failures = 0
        while (running) {
            // The full /proc walk in findPid touches every process's cmdline (~1000 reads on a
            // busy device); skip it while the pid we last injected is still alive, since it never
            // changes between keystore restarts. Fall back to the walk only once it's gone. The
            // fallback fires at most once per keystore restart (or per retry while injection keeps
            // failing), so log it; the common alive-pid path stays silent to keep the loop cheap.
            val pid =
                if (lastPid > 0 && isNamedProcess(lastPid, procName)) {
                    lastPid
                } else {
                    if (lastPid > 0) {
                        SystemLogger.debug(
                            "Injector: pid=$lastPid is no longer $procName; re-scanning /proc"
                        )
                    }
                    findPid(procName)
                }
            // Tell the log tail which process to capture, so the Logs panel shows the target
            // keystore's own output — even before we manage to inject it.
            LogTail.targetPid = if (pid > 0) pid else -1
            if (pid > 0 && pid != lastPid && serviceReady()) {
                when (inject(pid)) {
                    InjectionResult.SUCCEEDED -> {
                        lastPid = pid
                        failures = 0
                        SystemLogger.info("Injector: injected into $procName pid=$pid")
                        confirmAsync(pid)
                    }
                    InjectionResult.FAILED -> {
                        failures++
                        SystemLogger.warning("Injector: injection into pid=$pid failed; will retry")
                    }
                    InjectionResult.UNKNOWN -> {
                        // Unknown remote state is not a clean failure. Do not spend
                        // another 12 seconds polling for a hello: Control's existing
                        // event-driven socket reader will notice it if it arrives.
                        // Recovery can attempt injection only on a new Keystore PID.
                        lastPid = pid
                        failures = 0
                        SystemLogger.warning(
                            "Injector: pid=$pid quarantined until Keystore restarts; " +
                                "control channel may still recover asynchronously"
                        )
                    }
                }
            } else if (pid <= 0) {
                lastPid = -1 // process gone; force re-inject when it returns
            }
            // Back off when injection keeps failing so we don't hammer a wedged keystore.
            sleep(if (failures > 3) 10000 else 2000)
        }
    }

    /**
     * keystore forks before it registers its binder; wait for the service so we don't inject into a
     * half-initialised process.
     */
    private fun serviceReady(): Boolean {
        val name =
            if (api >= 31) "android.system.keystore2.IKeystoreService/default"
            else "android.security.keystore"
        return try {
            android.os.ServiceManager.getService(name) != null
        } catch (e: Throwable) {
            true // can't check (stub / older API): don't block injection
        }
    }

    /**
     * A successful remote entry now means the hook and listening control socket were both prepared,
     * but the lib hello is still the end-to-end proof that the daemon can reach this exact keystore
     * generation. Match the PID as well as the API: libApi used to survive a disconnect, so a new
     * keystore PID could accidentally be "confirmed" by the previous process's stale hello.
     *
     * Never blindly re-inject on a missing hello — entry already installed the hook, and a second
     * injection into the same PID could double-patch it. The control supervisor keeps reconnecting.
     */
    private fun confirmAsync(pid: Int) {
        Thread(
                {
                    for (i in 0 until 24) { // ~12s
                        if (Control.libApi != 0 && Control.libPid == pid) {
                            SystemLogger.info(
                                "Injector: confirmed $procName pid=$pid over the control channel " +
                                    "(hook=${Control.libHook} api=${Control.libApi})"
                            )
                            return@Thread
                        }
                        sleep(500)
                    }
                    val seenPid = Control.libPid
                    SystemLogger.warning(
                        "Injector: entry succeeded for pid=$pid but no matching lib hello arrived over " +
                            "${Const.CONTROL_SOCKET_PATH} (current hello pid=$seenPid); not re-injecting " +
                            "the same process because that risks double-hooking"
                    )
                },
                "teesim-inject-confirm",
            )
            .apply {
                isDaemon = true
                start()
            }
    }

    // A deadlocked native inject binary must not stall this watcher forever. If it times
    // out, its remote entry might already have installed the hook; do not try again in
    // the same PID because that could double-patch a live Keystore process.
    private enum class InjectionResult {
        SUCCEEDED,
        FAILED,
        UNKNOWN,
    }

    private fun inject(pid: Int): InjectionResult {
        try {
            val process =
                ProcessBuilder(
                        injectBin.absolutePath,
                        pid.toString(),
                        libFile.absolutePath,
                        "entry",
                    )
                    .redirectErrorStream(true)
                    .start()

            // Consume output concurrently to avoid pipe-buffer deadlock, retaining at
            // most 4096 characters. This runs only during an injection, never at idle.
            val captured = StringBuilder()
            val drainer =
                Thread(
                        {
                            try {
                                process.inputStream.use { stream ->
                                    val buffer = ByteArray(2048)
                                    while (true) {
                                        val read = stream.read(buffer)
                                        if (read < 0) break
                                        synchronized(captured) {
                                            val remain = 4096 - captured.length
                                            if (remain > 0) {
                                                captured.append(
                                                    String(buffer, 0, minOf(read, remain), Charsets.UTF_8)
                                                )
                                            }
                                        }
                                    }
                                }
                            } catch (_: Exception) {
                                // A killed native injector can close the pipe mid-read.
                            }
                        },
                        "teesim-inject-drain",
                    )
                    .apply {
                        isDaemon = true
                        start()
                    }

            if (!process.waitFor(15, TimeUnit.SECONDS)) {
                // The child may be inside a ptrace remote call with Keystore registers
                // temporarily replaced. SIGKILL would skip the injector's RAII register
                // restoration and PTRACE_DETACH. Leave it alone to finish safely.
                // The drainer stays alive (as a daemon thread) until the pipe closes.
                SystemLogger.warning(
                    "Injector: no completion after 15s for pid=$pid; " +
                        "native ptrace child left running for safe cleanup; " +
                        "refusing another injection into the same PID"
                )
                return InjectionResult.UNKNOWN
            }

            // The drainer is allowed a brief chance to finish writing the error excerpt;
            // its pipe is closed automatically when the injector exits.
            drainer.join(200)
            val code = process.exitValue()
            if (code != 0) {
                val excerpt = synchronized(captured) { captured.toString() }
                SystemLogger.warning("Injector: inject exit=$code output=$excerpt")
                return InjectionResult.FAILED
            }
            return InjectionResult.SUCCEEDED
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            // Do not kill a child that may currently own the ptrace attachment.
            SystemLogger.warning(
                "Injector: inject interrupted for pid=$pid; leaving native cleanup intact; " +
                    "hook state unknown; no same-PID retry"
            )
            return InjectionResult.UNKNOWN
        } catch (e: Exception) {
            SystemLogger.error("Injector: failed to start or run inject binary", e)
            return InjectionResult.FAILED
        }
    }

    /** True if /proc/[pid]/cmdline's basename still matches [name], else false. */
    private fun isNamedProcess(pid: Int, name: String): Boolean {
        val cmd =
            try {
                File("/proc/$pid/cmdline").readBytes()
            } catch (e: Exception) {
                return false
            }
        if (cmd.isEmpty()) return false
        val end = cmd.indexOf(0.toByte()).let { if (it < 0) cmd.size else it }
        return String(cmd, 0, end).substringAfterLast('/') == name
    }

    /** Return the pid whose /proc/<pid>/cmdline basename matches [name], else -1. */
    private fun findPid(name: String): Int {
        val proc = File("/proc")
        val entries =
            proc.listFiles { f -> f.isDirectory && f.name.all { it.isDigit() } } ?: return -1
        for (dir in entries) {
            val cmdlineFile = File(dir, "cmdline")
            val cmd =
                try {
                    cmdlineFile.readBytes()
                } catch (e: Exception) {
                    continue
                }
            if (cmd.isEmpty()) continue
            val end = cmd.indexOf(0.toByte()).let { if (it < 0) cmd.size else it }
            val arg0 = String(cmd, 0, end)
            val base = arg0.substringAfterLast('/')
            if (base == name) return dir.name.toIntOrNull() ?: continue
        }
        return -1
    }

    private fun sleep(ms: Long) {
        try {
            Thread.sleep(ms)
        } catch (ignored: InterruptedException) {}
    }
}
