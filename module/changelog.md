## 本 Fork 集成变更（2026-10-07）

- 新增 KeyMint / Keystore 行为一致性 CI 门禁，锁定非目标请求透传、严格硬件模式不降级、Android 10/11 事务表与 operation 生命周期等关键契约。
- 新增按配置方案独立控制的时序模型：证明、操作启动、TA 调用三类 0–2000 ms 有界随机延迟；默认全部关闭，不改变路由和返回值。
- 时序模型 WebUI 已完成简体中文适配，并加入范围/顺序校验与采样器测试。
- 同步上游 Injector PID 快速路径，减少不必要的 `/proc` 扫描。
- WebUI、安装提示、模块说明与新增诊断项完成简体中文适配。
- 集成 TEE / StrongBox 独立后端与严格硬件所有权校验，保留兼容与生成模式。
- Keybox 改为能力驱动：支持 RSA+EC、仅 EC、仅 RSA；导入前验证私钥与叶证书匹配、证书链链接和签名。
- 系统页新增 TEE / StrongBox 实机后端自检，可实际生成、使用并删除一次性测试密钥。
- CI 覆盖 WebUI/中文、Keybox/JVM、VINTF、硬件 blob、Rust Clippy、Release/Debug 构建与最终 ZIP smoke。
- OTA、Canary 与 WebUI 仓库链接固定到本 Fork，避免被上游构建覆盖。

---

## 🎉 TEESimulator 4.0 — a new foundation

Ever since TEESimulator began, the community has watched me pour real effort into closing
pre-existing detection points, release after release. But as AI-driven conformance scanners multiply
and quick "harness fix" commits go viral, it has grown exhausting to fold in a stream of unproven,
poorly-explained external patches — innovation stalled, and code quality slipped noticeably. 😮‍💨

So here is **TEESimulator 4.0**. 🚀 Instead of faking a hardware backend, it runs AOSP's own KeyMint
reference implementation — the very trusted application that normally lives *inside* the TEE —
**in-process**. This single change sweeps away countless detection points at once and, for the first
time, brings first-class permanent key storage. 🔐

## ✨ Highlights

- **🧠 Reference KeyMint TA, in-process.** Attestations come straight from AOSP's `kmr-ta`, not
  hand-rolled certificates — so every emitted record matches a real device field-for-field.
- **🎛️ Profiles and a WebUI.** Bundle a keybox, operation mode, patch/OS levels, and device identity
  into a named profile, assign it to your apps, and edit it all from the manager's WebUI — no text
  editor, no reboot.
- **📱 Android 10 → 17.** Both the legacy `keystore` daemon (Android 10/11) and `keystore2` / KeyMint
  (Android 12+) are intercepted, and every key is attested at — and reports — its real security level
  and the version its OS release uses.
- **🩹 Patch mode by default.** The real hardware still generates the key; only its attestation is
  re-signed under your keybox, keeping the genuine hardware-backed blob and its true contents.

## 💬 Feedback

To get started, drop a keybox at `/data/adb/teesim/keybox.xml`, then assign your apps to a profile in
the WebUI. 🗝️

Please open an issue for any device-support or compatibility problems — it helps enormously. 🙏 This
release has been tested on **Android 17 (Pixel 6)** and **Android 10 (the Android emulator)**.
