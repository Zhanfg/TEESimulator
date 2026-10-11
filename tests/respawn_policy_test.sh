#!/bin/sh
set -eu
. module/respawn_policy.sh
[ "$TEESIM_RESPAWN_DELAY" -eq 2 ]
for expected in 4 8 16 32 60 60; do
  teesim_backoff_after_exit 0
  [ "$TEESIM_RESPAWN_DELAY" -eq "$expected" ]
done
teesim_backoff_after_exit 29
[ "$TEESIM_RESPAWN_DELAY" -eq 60 ]
teesim_backoff_after_exit 30
[ "$TEESIM_RESPAWN_DELAY" -eq 2 ]
teesim_backoff_after_exit 1
[ "$TEESIM_RESPAWN_DELAY" -eq 4 ]
teesim_read_uptime_seconds
case "$TEESIM_UPTIME_SECONDS" in ''|*[!0-9]*) exit 1 ;; esac
printf '%s\n' 'respawn backoff fixtures PASS'
