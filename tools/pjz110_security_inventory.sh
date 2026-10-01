#!/system/bin/sh
# TES / OnePlus 13 (PJZ110 / CPH2653) security-backend inventory
#
# Read-only collector. It does NOT set properties, stop/start services, write vendor/system files,
# change SELinux, or touch key material. The only write is this report under Download.
#
# Usage: execute this .sh directly; no arguments are required.

set +e

STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null)"
[ -n "$STAMP" ] || STAMP="unknown-time"

OUT_DIR="/sdcard/Download"
[ -d "$OUT_DIR" ] || OUT_DIR="/storage/emulated/0/Download"
[ -d "$OUT_DIR" ] || OUT_DIR="."

OUT="$OUT_DIR/TES-PJZ110-security-inventory-$STAMP.log"
: > "$OUT" 2>/dev/null || {
  echo "Cannot create report: $OUT"
  exit 1
}

exec >>"$OUT" 2>&1

section() {
  echo
  echo "================================================================"
  echo "== $1"
  echo "================================================================"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

run() {
  echo
  echo "+ $*"
  "$@" 2>&1
}

grep_security() {
  grep -Ei 'keymint|keymaster|strongbox|sharedsecret|secureclock|remotelyprovision|remote.?provision|rkpd?|soter|ifaa|fingerprintpay|fido2?|cryptoeng|rpmb|widevine|oemcrypto|pki|drm' 2>/dev/null
}

echo "TES PJZ110 security-backend inventory"
echo "timestamp=$STAMP"
echo "uid=$(id -u 2>/dev/null)"
echo "user=$(id 2>/dev/null)"
echo "kernel=$(uname -a 2>/dev/null)"

section "1. Device / build identity"
for p in   ro.product.model   ro.product.device   ro.product.name   ro.product.vendor.device   ro.product.vendor.model   ro.build.version.release   ro.build.version.sdk   ro.build.fingerprint   ro.boot.prjname   ro.boot.hardware   ro.boot.product.hardware.sku   ro.vendor.oplus.market.name   ro.vendor.oplus.market.enname   ro.vendor.oplus.provision.pki   ro.device.security.level   remote_provisioning.enable_rkpd   vendor.wv.oemcrypto.debug.enable_prov40
do
  v="$(getprop "$p" 2>/dev/null)"
  printf '%-48s = %s\n' "$p" "$v"
done

section "2. Security-related properties"
getprop 2>/dev/null | grep_security | sort -u

section "3. Android feature declarations"
if have pm; then
  pm list features 2>/dev/null | grep_security
fi

section "4. Binder / service-manager inventory"
if have service; then
  service list 2>/dev/null | grep_security
else
  echo "service command unavailable"
fi

echo
echo "-- exact AIDL/HAL instances --"
for svc in   android.hardware.security.keymint.IKeyMintDevice/default   android.hardware.security.keymint.IKeyMintDevice/strongbox   android.hardware.security.keymint.IRemotelyProvisionedComponent/default   android.hardware.security.keymint.IRemotelyProvisionedComponent/strongbox   android.hardware.security.sharedsecret.ISharedSecret/default   android.hardware.security.sharedsecret.ISharedSecret/strongbox   android.hardware.security.secureclock.ISecureClock/default   android.hardware.security.secureclock.ISecureClock/strongbox   vendor.qti.hardware.soter.ISoter/default   vendor.oplus.hardware.biometrics.fingerprintpay.IFingerprintPay/default   vendor.oplus.hardware.fido.fidoca.IFidoDaemon/default   vendor.oplus.hardware.fido.fido2ca.IFidoDaemon/default   vendor.oplus.hardware.cryptoeng.ICryptoeng/default
do
  if have service; then
    printf '%-88s : ' "$svc"
    service check "$svc" 2>&1
  fi
done

section "5. Running processes"
if have ps; then
  ps -A -o PID,PPID,USER,NAME,ARGS 2>/dev/null | grep_security
  if [ $? -ne 0 ]; then
    ps -A 2>/dev/null | grep_security
  fi
fi

section "6. init service definitions"
for d in /vendor/etc/init /odm/etc/init /system_ext/etc/init /product/etc/init; do
  [ -d "$d" ] || continue
  echo
  echo "-- $d --"
  grep -R -n -Ei 'keymint|keymaster|strongbox|sharedsecret|secureclock|soter|ifaa|fingerprintpay|fido2?|cryptoeng|rpmb|widevine|rkp|pki' "$d" 2>/dev/null | head -n 1200
done

section "7. VINTF manifests"
for d in   /vendor/etc/vintf   /odm/etc/vintf   /system/etc/vintf   /system_ext/etc/vintf   /product/etc/vintf
do
  [ -d "$d" ] || continue
  echo
  echo "-- $d --"
  grep -R -n -Ei 'keymint|strongbox|sharedsecret|secureclock|remotelyprovision|soter|ifaa|fingerprintpay|fido2?|cryptoeng|rpmb|widevine|rkp|pki' "$d" 2>/dev/null | head -n 1600
done

section "8. SELinux service/property contexts"
for f in   /vendor/etc/selinux/vendor_service_contexts   /vendor/etc/selinux/vendor_property_contexts   /odm/etc/selinux/vendor_service_contexts   /odm/etc/selinux/vendor_property_contexts   /odm/etc/selinux/precompiled_service_contexts   /odm/etc/selinux/precompiled_property_contexts   /system/etc/selinux/plat_service_contexts   /system/etc/selinux/plat_property_contexts   /vendor_service_contexts   /vendor_property_contexts
do
  [ -f "$f" ] || continue
  echo
  echo "-- $f --"
  grep -n -Ei 'keymint|strongbox|sharedsecret|secureclock|soter|ifaa|fingerprintpay|fido2?|cryptoeng|rpmb|widevine|rkp|pki' "$f" 2>/dev/null | head -n 1200
done

section "9. Security backend files"
for root in   /vendor/bin /vendor/bin/hw /vendor/lib64 /vendor/etc   /odm/bin /odm/bin/hw /odm/lib64 /odm/etc   /system_ext/app /system_ext/priv-app /system_ext/lib64   /product/app /product/priv-app /product/lib64
do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 5 -type f 2>/dev/null     | grep -Ei '/[^/]*(keymint|keymaster|strongbox|sharedsecret|secureclock|soter|ifaa|fingerprintpay|fido2?|cryptoeng|rpmb|widevine|oemcrypto|rkp|pki)[^/]*$'
done | sort -u

section "10. RPMB device / sysfs evidence"
for p in   /dev/*rpmb*   /dev/block/*rpmb*   /sys/block/*rpmb*   /sys/class/block/*rpmb*
do
  [ -e "$p" ] && ls -ld "$p" 2>/dev/null
done

# UFS RPMB BSG nodes on recent Qualcomm platforms are not always named "rpmb".
for p in /dev/0:0:0:* /dev/bsg/*; do
  [ -e "$p" ] && ls -ld "$p" 2>/dev/null
done | head -n 300

section "11. Key OEM packages"
if have pm; then
  for pkg in     com.oplus.engineermode     com.tencent.soter.soterserver     com.android.rkpdapp     com.google.android.rkpdapp
  do
    echo
    echo "-- $pkg --"
    pm path "$pkg" 2>/dev/null
    dumpsys package "$pkg" 2>/dev/null       | grep -Ei 'versionName|versionCode|codePath|resourcePath|nativeLibrary|primaryCpuAbi|secondaryCpuAbi|enabled='       | head -n 160
  done
fi

section "12. EngineerMode static keyword inventory (best effort)"
ENGINEER_APK=""
if have pm; then
  ENGINEER_APK="$(pm path com.oplus.engineermode 2>/dev/null | head -n 1 | sed 's/^package://')"
fi
echo "EngineerMode APK: $ENGINEER_APK"

if [ -n "$ENGINEER_APK" ] && [ -f "$ENGINEER_APK" ]; then
  if have unzip; then
    echo
    echo "-- archive entries related to native/security code --"
    unzip -l "$ENGINEER_APK" 2>/dev/null       | grep -Ei 'lib/|classes[0-9]*\.dex|security|key|rkp|soter|widevine|pki|fido|crypto'       | head -n 800

    if have strings; then
      echo
      echo "-- DEX strings (selected security terms) --"
      unzip -l "$ENGINEER_APK" 2>/dev/null         | awk '/classes([0-9]+)?\.dex$/ {print $4}'         | while IFS= read -r dex; do
            [ -n "$dex" ] || continue
            echo "### $dex"
            unzip -p "$ENGINEER_APK" "$dex" 2>/dev/null               | strings 2>/dev/null               | grep -Ei 'SecurityInterface|PKI|PKI.?Group|genRkpInfo|isSupportRkpWidevine|queryDrmInfo|isGoogleKeyImport|verifyAttkKeyPair|Soter|FIDO2?|cryptoeng|widevine|rpmb|keymint|strongbox'               | sort -u               | head -n 1000
          done
    else
      echo "strings command unavailable; skipping DEX keyword extraction"
    fi
  else
    echo "unzip command unavailable; skipping APK static inventory"
  fi
fi

section "13. HIDL inventory (if lshal exists)"
if have lshal; then
  lshal 2>/dev/null | grep_security | head -n 1200
else
  echo "lshal unavailable"
fi

section "14. DRM / Widevine runtime summary (best effort)"
if have dumpsys; then
  dumpsys media.drm 2>/dev/null     | grep -Ei 'widevine|oemcrypto|security.?level|provision|hdcp|drm'     | head -n 800
fi

section "15. Relevant init.svc properties"
getprop 2>/dev/null   | grep -Ei 'init\.svc\..*(keymint|strongbox|soter|fido|cryptoeng|fingerprintpay|rpmb|widevine|rkpd)'   | sort -u

section "16. Summary hints"
echo "Expected OnePlus 13 / SM8750 baseline from public stock-derived sources:"
echo "  TEE:       QTI IKeyMintDevice/default"
echo "  StrongBox: NXP IKeyMintDevice/strongbox"
echo "  SB RKP:    IRemotelyProvisionedComponent/strongbox"
echo "  SB secret: ISharedSecret/strongbox"
echo "  Soter:     vendor.qti.hardware.soter.ISoter/default"
echo "  IFAA:      vendor.oplus.hardware.biometrics.fingerprintpay.IFingerprintPay/default"
echo
echo "Still being resolved for PJZ110 specifically:"
echo "  FIDO / FIDO2, cryptoeng, PKI / PKI Group, RKP-Widevine provider"
echo
echo "Report complete: $OUT"
