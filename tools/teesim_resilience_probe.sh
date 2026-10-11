#!/system/bin/sh
# TEESimulator startup / survival report. Read-only. No args, no secrets printed.
umask 077
OUTDIR=/sdcard/Download
[ -d "$OUTDIR" ] || OUTDIR=/data/local/tmp
STAMP=$(date +%Y%m%d_%H%M%S 2>/dev/null)
OUT="$OUTDIR/TEESimulator_Resilience_${STAMP:-report}.txt"

if [ "$(id -u 2>/dev/null)" != 0 ]; then
  echo "Please run this script in a root shell (su). No arguments needed."
  exit 1
fi

report() {
  printf '%s\n' 'TEESimulator startup/resilience report'
  printf 'UTC: '; date -u '+%Y-%m-%d %H:%M:%S' 2>/dev/null
  printf 'SDK: '; getprop ro.build.version.sdk 2>/dev/null
  printf 'Boot completed: '; getprop sys.boot_completed 2>/dev/null
  printf 'SELinux: '; getenforce 2>/dev/null
  printf 'Kernel release: '; uname -r
  printf '\nModule presence:\n'
  for path in /data/adb/modules/teesim /data/adb/modules_update/teesim; do
    if [ -d "$path" ]; then
      echo "$path : exists"
      for f in service.sh supervisor.sh boot-completed.sh respawn_policy.sh daemon classes.dex service.apk disable remove; do
        [ -e "$path/$f" ] && echo "  $f: present"
      done
    else
      echo "$path : absent"
    fi
  done
  printf '\nSupervisor state (only exit codes and durations):\n'
  if [ -r /data/adb/teesim/supervisor_state ]; then
    cat /data/adb/teesim/supervisor_state
  else
    echo "not available (older build / supervisor not launched)"
  fi
  if [ -r /data/adb/teesim/supervisor.lock/pid ]; then
    IFS= read -r spid < /data/adb/teesim/supervisor.lock/pid
    case "$spid" in
      ''|*[!0-9]*) echo "supervisor PID: invalid" ;;
      *)
        if kill -0 "$spid" 2>/dev/null; then
          echo "supervisor PID: alive"
          printf 'supervisor oom_score_adj: '
          cat "/proc/$spid/oom_score_adj" 2>/dev/null || echo unknown
        else
          echo "supervisor PID: stale"
        fi ;;
    esac
  else
    echo "supervisor lock: absent"
  fi
  printf '\nProcess snapshots:\n'
  for name in teesim keystore2 keystore; do
    found=$(pidof "$name" 2>/dev/null)
    if [ -z "$found" ]; then
      echo "$name: not running"
      continue
    fi
    for pid in $found; do
      echo "$name PID: $pid"
      if [ -r "/proc/$pid/status" ]; then
        awk '/^State:|^VmRSS:|^Threads:/{print "  " $0}' "/proc/$pid/status"
      fi
      printf '  oom_score_adj: '
      cat "/proc/$pid/oom_score_adj" 2>/dev/null || echo unknown
    done
  done
  printf '\nEvent counts from a limited logcat window (no raw logs or identifiers):\n'
  logcat -d -t 4000 -s TEESimulator:I 2>/dev/null | awk '
    /App: daemon starting/ { start++ }
    /App: daemon initialised/ { ready++ }
    /system_server.*unavailable|system context unavailable|App: fatal error/ { startup_err++ }
    /Injector: injection into pid=.*failed|inject FAILED/ { injector_err++ }
    /Control: connection error/ { control_err++ }
    /KeyAdmin: accept error/ { admin_err++ }
    END {
      printf "daemon_start=%d initialized=%d startup_failure=%d injection_failure=%d control_errors=%d admin_socket_errors=%d\n",
        start, ready, startup_err, injector_err, control_err, admin_err
    }'
  printf '\nEND (no key material, token, keybox or raw logcat collected)\n'
}
report > "$OUT" 2>&1
chmod 0600 "$OUT" 2>/dev/null || :
echo "Report saved to: $OUT"
