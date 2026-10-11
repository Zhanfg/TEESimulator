#!/system/bin/sh
# Crash-loop backoff policy. Sourced by service.sh. No external commands or timers.
TEESIM_RESPAWN_DELAY=2

teesim_read_uptime_seconds() {
  if IFS=' ' read -r teesim_up teesim_rest </proc/uptime; then
    TEESIM_UPTIME_SECONDS=${teesim_up%%.*}
  else
    TEESIM_UPTIME_SECONDS=0
  fi
  case "$TEESIM_UPTIME_SECONDS" in
    ''|*[!0-9]*) TEESIM_UPTIME_SECONDS=0 ;;
  esac
}

# Called after sleeping the current delay; a run lasting >=30s is considered
# recovered, while repeated quick exits back off to at most 60s.
teesim_backoff_after_exit() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  if [ "$1" -ge 30 ]; then
    TEESIM_RESPAWN_DELAY=2
  elif [ "$TEESIM_RESPAWN_DELAY" -lt 60 ]; then
    TEESIM_RESPAWN_DELAY=$((TEESIM_RESPAWN_DELAY * 2))
    if [ "$TEESIM_RESPAWN_DELAY" -gt 60 ]; then
      TEESIM_RESPAWN_DELAY=60
    fi
  fi
}
