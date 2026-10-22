#!/bin/sh
set -eu
# Fully unprivileged smoke test: no Android/root access, no real KeyMint keys.
tmp=$(mktemp -d)
supervisor_pid=''
cleanup() {
  if [ -n "$supervisor_pid" ]; then kill "$supervisor_pid" 2>/dev/null || :; wait "$supervisor_pid" 2>/dev/null || :; fi
  rm -rf "$tmp"
}
trap 'cleanup' 0
mkdir -p "$tmp/mod" "$tmp/state"
cp module/supervisor.sh module/respawn_policy.sh "$tmp/mod/"
cat > "$tmp/mod/daemon" <<'END_DAEMON'
#!/bin/sh
exit 23
END_DAEMON
chmod 0755 "$tmp/mod/daemon"

TEESIM_SHELL=/bin/sh TEESIM_STATE_DIR="$tmp/state" \
  sh "$tmp/mod/supervisor.sh" "$tmp/mod" >/dev/null 2>&1 &
supervisor_pid=$!

tries=0
while [ ! -s "$tmp/state/supervisor_state" ] && [ "$tries" -lt 80 ]; do
  sleep 0.1
  tries=$((tries + 1))
done
[ -s "$tmp/state/supervisor_state" ] || { echo 'supervisor never recorded child exit'; exit 1; }
grep -q '^last_exit=23 runtime_s=' "$tmp/state/supervisor_state"
[ "$(cat "$tmp/state/supervisor.lock/pid")" = "$supervisor_pid" ]

# A second boot trigger must NOT duplicate the manager or its child.
TEESIM_SHELL=/bin/sh TEESIM_STATE_DIR="$tmp/state" \
  sh "$tmp/mod/supervisor.sh" "$tmp/mod" >/dev/null 2>&1
[ "$(cat "$tmp/state/supervisor.lock/pid")" = "$supervisor_pid" ]

kill "$supervisor_pid"
wait "$supervisor_pid" 2>/dev/null || :
supervisor_pid=''
[ ! -d "$tmp/state/supervisor.lock" ] || { echo 'supervisor lock not cleaned up'; exit 1; }
echo 'supervisor lifecycle fixture PASS'
