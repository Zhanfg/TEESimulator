#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
km = (ROOT / "keymint/keymint_router.cpp").read_text(encoding="utf-8")
ks1 = (ROOT / "keystore/keystore_router.cpp").read_text(encoding="utf-8")

errors = []

def require(text: str, needle: str, label: str):
    if needle not in text:
        errors.append(f"{label}: missing {needle!r}")

def require_re(text: str, pattern: str, label: str):
    if re.search(pattern, text, re.S) is None:
        errors.append(f"{label}: pattern did not match: {pattern}")

# Every current IKeyMintDevice entry point must remain explicitly implemented in the wrapper.
device_methods = [
    "getHardwareInfo", "generateKey", "importKey", "begin", "deleteKey", "upgradeKey",
    "getKeyCharacteristics", "convertStorageKeyToEphemeral", "addRngEntropy",
    "importWrappedKey", "deleteAllKeys", "destroyAttestationIds", "deviceLocked",
    "earlyBootEnded", "getRootOfTrustChallenge", "getRootOfTrust", "sendRootOfTrust",
    "setAdditionalAttestationInfo",
]
for method in device_methods:
    require_re(
        km,
        rf"ndk::ScopedAStatus\s+{re.escape(method)}\s*\([^{{;]*\)\s*override",
        f"IKeyMintDevice.{method}",
    )

# Operation lifecycle must be wrapped for both local-TA and forwarded real-HAL operations.
for method in ["updateAad", "update", "finish", "abort"]:
    count = len(re.findall(rf"ndk::ScopedAStatus\s+{method}\s*\(", km))
    if count < 2:
        errors.append(f"IKeyMintOperation.{method}: expected local + forwarded implementations, got {count}")

# Non-target requests must fall through untouched to the genuine backend.
require(km, "forwarding to real HAL (not a target)", "non-target generate/import forwarding")
require(km, "if (!t.ta)", "target routing gate")

# Strict hardware is ownership, not a label: legacy TES software blobs may never execute there.
strict_markers = [
    "strict hardware mode has no real",
    "strict hardware profile attempted to use legacy TES software key",
    "strict hardware profile cannot upgrade legacy TES software key",
    "strict hardware profile still owns legacy TES software key",
    "strict hardware profile supplied a TES software wrapping key",
]
for marker in strict_markers:
    require(km, marker, "strict-hardware fail-closed contract")
require(km, "ErrorCode::INVALID_KEY_BLOB", "strict-hardware invalid legacy blob error")
require(km, "RequireBackendLifecycleSynced", "hardware lifecycle synchronization gate")
require(km, "ValidateKnownHardwareBlobDomain", "hardware-domain ownership gate")

# The real HAL's status must be returned directly on forwarded operations.
for marker in [
    "return real_->getHardwareInfo(info);",
    "return real_ ? real_->addRngEntropy(data) : ndk::ScopedAStatus::ok();",
    "auto st = real_->begin",
    "auto st = real_->finish",
]:
    require(km, marker, "forwarded status propagation")

# Android 10/11 legacy binder ABI: transaction ordinals are intentionally release-specific.
require(ks1, "constexpr TxCodes kTxQ = {18, 19, 21, 29, 22, 23, 24, 25};", "Android 10 transaction table")
require(ks1, "constexpr TxCodes kTxR = {17, 18, 20, 28, 21, 22, 23, 24};", "Android 11 transaction table")
require(ks1, "operation token not one of ours; forwarding to the real keystore", "unknown operation-token forwarding")
require(ks1, "is a %s key, not asymmetric; forwarding to the real keystore", "legacy symmetric-key forwarding")

# Timing is presentation-only and scoped to a selected profile.
require(km, 'ApplyTimingDelay(t.timing.attestation, "attestation", t.id)', "attestation timing scope")
require(km, 'ApplyTimingDelay(current.timing.operation_start, "operation-start", current.id)', "begin timing scope")
require(km, 'ApplyTimingDelay(ta_call_delay_, "ta-call", "")', "operation TA timing")
require(ks1, 'ApplyTimingDelay(timing.attestation, "attestation", uid)', "legacy attestation timing")
require(ks1, 'ApplyTimingDelay(timing.operation_start, "operation-start", uid)', "legacy begin timing")
require(ks1, 'if (code == tx.attestKey) ApplyTimingDelay(timing.attestation, "attestation", uid);',
        "legacy strict-hardware attestation timing")
require(ks1, 'if (code == tx.begin) ApplyTimingDelay(timing.operation_start, "operation-start", uid);',
        "legacy strict-hardware begin timing")

if errors:
    print("KeyMint/Keystore behavioral contract FAILED:", file=sys.stderr)
    for e in errors:
        print(" -", e, file=sys.stderr)
    sys.exit(1)

print(f"KeyMint/Keystore behavioral contract OK: {len(device_methods)} device methods + operation/legacy gates")
