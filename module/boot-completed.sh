#!/system/bin/sh
# One-shot recovery if late_start's supervisor died before Android finished booting.
# supervisor.sh's atomic directory lock prevents a second instance.
MODDIR=${0%/*}
/system/bin/sh "$MODDIR/service.sh" >/dev/null 2>&1
