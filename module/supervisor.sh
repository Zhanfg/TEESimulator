#!/system/bin/sh
# Single-instance, event-driven supervisor: wait(2) on the daemon, no periodic polling.
MODDIR=${1:-${0%/*}}
STATE_DIR=${TEESIM_STATE_DIR:-/data/adb/teesim}
LOCK_DIR="$STATE_DIR/supervisor.lock"
mkdir -p "$STATE_DIR" || exit 1

# A second entry from boot-completed.sh must not duplicate the Keystore hook.
# Validate the old PID's command line to reject stale/recycled PID files.
teesim_supervisor_alive() {
  old_pid=''
  [ -r "$LOCK_DIR/pid" ] && IFS= read -r old_pid < "$LOCK_DIR/pid"
  case "$old_pid" in ''|*[!0-9]*) return 1 ;; esac
  [ "$old_pid" -ne "$$" ] || return 0
  kill -0 "$old_pid" 2>/dev/null || return 1
  [ -r "/proc/$old_pid/cmdline" ] || return 1
  tr '\000' '\n' < "/proc/$old_pid/cmdline" | grep -F -x "$MODDIR/supervisor.sh" >/dev/null 2>&1
}

teesim_take_lock() {
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    # Give an in-flight lock creator time to publish its PID.
    if [ ! -s "$LOCK_DIR/pid" ]; then sleep 1; fi
    if teesim_supervisor_alive; then return 1; fi
    # Stale lock after SIGKILL/reboot. Retrying mkdir is atomic.
    rm -f "$LOCK_DIR/pid" 2>/dev/null || return 1
    rmdir "$LOCK_DIR" 2>/dev/null || return 1
    mkdir "$LOCK_DIR" 2>/dev/null || return 1
  fi
  printf '%s\n' "$$" > "$LOCK_DIR/pid" || return 1
}

teesim_take_lock || exit 0
child_pid=''
teesim_cleanup() {
  if [ -n "$child_pid" ]; then
    kill "$child_pid" 2>/dev/null || :
  fi
  stored_pid=''
  [ -r "$LOCK_DIR/pid" ] && IFS= read -r stored_pid < "$LOCK_DIR/pid"
  if [ "$stored_pid" = "$$" ]; then
    rm -f "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null || :
  fi
}
trap 'teesim_cleanup' 0
trap 'exit 0' 1 2 15

# Preserve the root manager's existing oom_score_adj. Real PJZ110 Android 17 evidence
# shows the daemon at -1000 already; changing it to -300 would REDUCE protection.
# There is no wake-lock, VM-global tuning, or other runtime priority override.

. "$MODDIR/respawn_policy.sh"

while [ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ]; do
  teesim_read_uptime_seconds
  started_at=$TEESIM_UPTIME_SECONDS
  # Run as a direct child. The shell blocks in wait; screen-off adds no wakeups.
  "${TEESIM_SHELL:-/system/bin/sh}" "$MODDIR/daemon" "$MODDIR" &
  child_pid=$!
  wait "$child_pid"
  status=$?
  child_pid=''
  teesim_read_uptime_seconds
  run_seconds=$((TEESIM_UPTIME_SECONDS - started_at))
  [ "$run_seconds" -ge 0 ] || run_seconds=0

  # One compact diagnostic record per exit, no unbounded log/flash growth.
  printf 'last_exit=%s runtime_s=%s retry_s=%s\n' "$status" "$run_seconds" "$TEESIM_RESPAWN_DELAY" > "$STATE_DIR/supervisor_state" 2>/dev/null || :
  sleep "$TEESIM_RESPAWN_DELAY"
  teesim_backoff_after_exit "$run_seconds"
done
