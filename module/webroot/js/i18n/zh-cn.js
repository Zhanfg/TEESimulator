// Simplified-Chinese localization layer for the TEESimulator WebUI.
//
// This file intentionally translates presentation text only. It never rewrites config values,
// package names, aliases, key blobs, logs from native code, or protocol payloads. That keeps the
// localization independent from KeyMint/TEE behavior and safe to carry across upstream merges.

const EXACT = new Map(Object.entries({
  "checking…": "检查中…",
  "running": "运行中",
  "unreachable": "不可连接",

  "Profiles": "配置方案",
  "Keyboxes": "Keybox",
  "Keys": "密钥",
  "System": "系统",
  "Logs": "日志",
  "Sections": "页面导航",
  "update available": "有可用更新",

  "Add profile": "添加配置方案",
  "No profiles yet. Add one to start attesting for apps.": "还没有配置方案。添加一个方案后即可为目标应用处理密钥证明。",
  "Unsaved changes": "有未保存的更改",
  "Save": "保存",
  "Back to profiles": "返回配置方案",
  "Edit profile": "编辑配置方案",
  "Profile name": "配置方案名称",
  "Attestation": "密钥证明",
  "Patch & OS levels": "补丁与系统版本",
  "Device identity": "设备身份",
  "Target apps": "目标应用",
  "Each overrides one attested device id. Leave a field empty to use the value harvested from the device.": "每一项都会覆盖对应的设备证明标识。留空则使用从当前设备采集到的值。",
  "optional": "可选",
  "not harvested — this tag will be omitted": "未采集到——将省略此标签",
  "from the device build property; omitted if unset": "读取设备构建属性；属性不存在时省略",
  "Leave a patch, OS, or identity field empty to use the value ": "补丁、系统或身份字段留空时，将使用",
  "harvested from this device": "从当前设备采集的值",
  "Remove profile": "删除配置方案",
  "Ready to save": "可以保存",

  "Keybox": "Keybox",
  "Operation mode": "运行模式",
  "hardware": "硬件（严格）",
  "patch": "补丁（兼容）",
  "generation": "生成（兼容）",
  "hardware (recommended): real TEE/StrongBox owns key material and operations; hardware failure is returned instead of falling back to software. patch (compatibility): prefer real hardware and re-sign its attestation, but may fall back to the in-process compatibility TA. generation (compatibility): mint the whole key in that software TA.": "硬件（推荐）：密钥材料与运算真正由 TEE/StrongBox 持有，硬件失败会直接返回，不回退到软件。补丁（兼容）：优先使用真实硬件并重签证明，必要时可回退到进程内兼容 TA。生成（兼容）：整个密钥在软件 TA 中生成。",
  "System patch": "系统补丁级别",
  "Vendor patch": "厂商补丁级别",
  "Boot patch": "启动补丁级别",
  "OS version": "系统版本",
  "Brand": "品牌",
  "Device": "设备代号",
  "Product": "产品",
  "Manufacturer": "制造商",
  "Model": "型号",
  "Serial": "序列号",
  "Apps": "应用",
  "The apps this profile attests for.": "此配置方案生效的目标应用。",
  "Auto-include new apps": "自动包含新应用",
  "Targets apps installed after now; existing apps stay untouched. New apps are discovered on a rescan, not watched for live.": "自动包含此后安装的应用；已有应用保持不变。新应用会在重新扫描时发现，而不是实时监听。",
  "no keybox files found": "未找到 Keybox 文件",
  "No apps yet.": "尚未添加应用。",
  "Add": "添加",
  "Configure scope →": "配置作用范围 →",
  "No apps": "无应用",
  "Used by profile “": "已由配置方案“",
  "Auto-include on — no new apps in scope yet.": "已开启自动包含——目前还没有新应用进入作用范围。",

  "Stored keys": "已存储密钥",
  "Loading…": "加载中…",
  "Daemon key capability unavailable.": "守护进程的密钥管理能力不可用。",
  "The daemon's admin endpoint isn't reachable yet; keys can't be listed.": "尚无法连接守护进程管理端点，因此无法列出密钥。",
  "Key listing is not available on this Android version.": "此 Android 版本不支持列出密钥。",
  "This module hasn't minted any keys for the target apps yet.": "此模块尚未为目标应用生成任何密钥。",
  "Deleting…": "正在删除…",
  "Play Integrity may be outside TEESimulator's control.": "Play Integrity 可能未受 TEESimulator 控制。",
  "All": "全部",
  "Spoofed": "TES 处理",
  "No keys.": "没有密钥。",
  "Selection actions": "选择操作",
  "Select filtered": "选择筛选结果",
  "Select all": "全选",
  "Unselect all": "取消全选",
  "Inverse selection": "反选",
  "Only keys this module spoofed": "仅显示由 TES 处理的密钥",
  "Include the apps' own real device keys": "同时显示应用自己的真实设备密钥",
  "No real keys to hide": "没有可隐藏的真实密钥",
  "Generated": "生成",
  "Delegated": "委托证明",
  "Patched": "补丁模式",
  "Untouched": "未处理",
  "Algorithm": "算法",
  "Created": "创建时间",

  "Import": "导入",
  "No keyboxes yet. Import an *.xml keybox to sign attestations with.": "还没有 Keybox。导入一个 *.xml Keybox 后即可用于签署密钥证明。",
  "Rename": "重命名",
  "Delete": "删除",
  "Import keybox": "导入 Keybox",
  "Close": "关闭",
  "Keybox file": "Keybox 文件",
  "Save as": "保存为",
  "Could not inspect this keybox.": "无法检查此 Keybox。",
  "No <Key> blocks found in this keybox.": "此 Keybox 中未找到 <Key> 节点。",
  "Back to keyboxes": "返回 Keybox",
  "chain ok": "证书链正常",
  "chain broken": "证书链损坏",
  "single cert": "单证书",
  "private key": "含私钥",
  "no private key": "无私钥",
  "Revoked by Google": "已被 Google 吊销",
  "A certificate in this chain is on Google's revocation list — attestations it signs are rejected by Play Integrity.": "此证书链中存在 Google 吊销列表里的证书；由它签署的证明会被 Play Integrity 拒绝。",
  "Chain does not verify": "证书链验证失败",
  "A certificate signature in this chain is invalid, so it is not a usable attestation chain.": "证书链中存在无效签名，因此无法作为有效的密钥证明链使用。",
  "Signed by Google": "Google 签名",
  "Roots in the Google Hardware Attestation key": "根证书属于 Google Hardware Attestation",
  "Samsung Knox root": "Samsung Knox 根证书",
  "AOSP software root": "AOSP 软件根证书",
  "Rooted in the AOSP software test key — not a hardware-backed keybox; fails hardware attestation.": "根证书是 AOSP 软件测试密钥——这不是硬件支持的 Keybox，无法通过硬件证明。",
  "Unknown root": "未知根证书",
  "Chain does not root in a recognized attestation authority": "证书链未锚定到已识别的密钥证明机构",
  "revoked": "已吊销",
  "bad signature": "签名无效",
  "expired": "已过期",
  "not yet valid": "尚未生效",
  "subject": "主题",
  "issuer": "签发者",
  "serial": "序列号",
  "revocation": "吊销状态",
  "valid": "有效",
  "leaf": "叶证书",
  "root": "根证书",
  "intermediate": "中间证书",

  "Filter": "筛选",
  "Pause": "暂停",
  "Resume": "继续",
  "Scroll to top": "滚动到顶部",
  "Scroll to bottom": "滚动到底部",
  "Minimum level": "最低日志级别",
  "No tags seen yet.": "尚未发现日志标签。",
  "Filter logs": "筛选日志",
  "Tags": "标签",
  "Message contains": "消息包含",
  "Reset filters": "重置筛选",
  "Save logs": "保存日志",
  "Folder": "目录",
  "Filename": "文件名",
  "substring in the message": "消息内容中的子串",
  "daemon unreachable": "守护进程不可连接",

  "Remote Key Provision": "远程密钥供应（RKP）",
  "TEE RKP-only": "TEE 仅使用 RKP",
  "When on, the TEE security level provisions attestation keys only via RKP, with no batch-key fallback.": "开启后，TEE 安全级别仅通过 RKP 获取证明密钥，不再回退到批量证明密钥。",
  "StrongBox RKP-only": "StrongBox 仅使用 RKP",
  "When on, the StrongBox security level provisions attestation keys only via RKP, with no batch-key fallback.": "开启后，StrongBox 安全级别仅通过 RKP 获取证明密钥，不再回退到批量证明密钥。",
  "Enable rkpd": "启用 rkpd",
  "Whether the native remote key provisioning daemon (rkpd) runs on this device.": "控制本机原生远程密钥供应守护进程（rkpd）是否运行。",
  "RKP enabled (OEM)": "RKP 状态（OEM）",
  "Read-only effective RKP state exposed by some OEM stacks such as ColorOS/OxygenOS. This is a status signal, not a knob TEESimulator should rewrite.": "部分 OEM 栈（如 ColorOS/OxygenOS）暴露的只读 RKP 实际状态。这里只用于显示状态，TEESimulator 不应改写该值。",
  "You usually don't need to change these.": "通常不需要修改这些选项。",
  "The module handles remote provisioning while these stay on. Only if a device explicitly fails keybox attestation — a rare case — should you toggle them all off to force keystore2 onto the keybox.": "保持开启时，模块会正常处理远程密钥供应。只有设备明确出现 Keybox 证明失败这种少见情况时，才建议全部关闭，以强制 keystore2 使用 Keybox。",
  "read only": "只读",
  "EC-only": "仅 EC",
  "RSA-only": "仅 RSA",
  "RSA+EC": "RSA+EC",
  "The file is copied into /data/adb/teesim; the name field becomes its filename.": "文件会复制到 /data/adb/teesim；名称字段将作为文件名。",

  "Back to profile": "返回配置方案",
  "Search apps, packages, users, or uid…": "搜索应用、包名、用户或 UID…",
  "Search": "搜索",
  "Sort order": "排序方式",
  "All users": "所有用户",
  "Reading installed apps…": "正在读取已安装应用…",
  "Could not read the device app list": "无法读取设备应用列表",
  "Clear": "清除",
  "Invert": "反选",
  "Clear usage": "清除使用记录",
  "Auto-include is idle until the package baseline is seeded.": "在建立应用基线之前，自动包含暂不生效。",
  "Auto-include is on — dashed apps are in scope automatically. Tap one to pin it here.": "已开启自动包含——虚线应用会自动进入作用范围；点击可将其固定到此配置。",
  "Auto-include updates when you save.": "保存后自动包含设置才会生效。",
  "Not installed": "未安装",
  "Done": "完成",
  "No apps found on the device.": "设备上未找到应用。",
  "No app has requested a key since boot yet.": "本次开机后还没有应用请求过密钥。",
  "Nothing in scope yet — tap an app to add it.": "作用范围目前为空——点击应用即可添加。",
  "No apps match.": "没有匹配的应用。",
  "work": "工作资料",
  "managed": "受管理",
  "system uid": "系统 UID",
  "auto": "自动",
  "Requested a key since boot": "本次开机后请求过密钥",
  "Already targeted by profile ": "已由配置方案处理：",

  "Harvest": "硬件采集",
  "No harvest record yet.": "还没有硬件采集记录。",
  "TrustedEnvironment": "可信执行环境（TEE）",
  "StrongBox": "StrongBox",
  "No key was attestable (common on certain models after unlocking the bootloader), so nothing was captured — every value below is synthesized.": "没有可完成证明的密钥（某些机型解锁 Bootloader 后较常见），因此未采集到真实值——下方值均为合成值。",
  "StrongBox has no working hardware on this device; keys requested at StrongBox are generated (not patched) at the TEE version.": "此设备没有可工作的 StrongBox 硬件；请求 StrongBox 的密钥将按兼容路径处理。",
  "Captured": "真实采集",
  "Fabricated": "呈现覆盖",
  "required": "必需",
  "supplement": "补充",
  "synthesized": "合成",
  "edited": "已编辑",
  "Software": "软件",
  "Verified": "已验证",
  "SelfSigned": "自签名",
  "Unverified": "未验证",
  "Failed": "失败",
  "all zero": "全零",

  "Backend self-test": "后端自检",
  "Creates throwaway AndroidKeyStore keys and actually uses them to verify TEE/StrongBox provenance plus RSA, AES-GCM and HMAC behaviour. Test keys are deleted afterwards.": "创建一次性 AndroidKeyStore 测试密钥并实际执行操作，用于验证 TEE/StrongBox 来源以及 RSA、AES-GCM、HMAC 行为；测试密钥随后会删除。",
  "Not run yet.": "尚未运行。",
  "Run self-test": "运行自检",
  "Testing…": "正在测试…",
  "Backend self-test failed": "后端自检失败",
  "Available": "可用",
  "Unavailable": "不可用",
  "EC P-256 generate/sign/verify": "EC P-256 生成/签名/验证",
  "Provenance matches requested level": "来源与请求安全级别一致",
  "RSA-2048 sign/verify": "RSA-2048 签名/验证",
  "AES-128-GCM round trip": "AES-128-GCM 往返验证",
  "HMAC-SHA256": "HMAC-SHA256",
  "pass": "通过",
  "fail": "失败",
  "Update": "更新",
  "Checking for updates…": "正在检查更新…",
  "Update status unavailable — daemon unreachable.": "无法获取更新状态——守护进程不可连接。",
  "Installed": "当前版本",
  "No canary release has been published yet.": "尚未发布 Canary 版本。",
  "On the latest canary.": "当前已是最新 Canary。",
  "Update available": "有可用更新",
  "What's new": "更新内容",
  "Build variant": "构建版本",
  "Downloading & flashing…": "正在下载并刷入…",
  "Installing…": "正在安装…",
  "Install": "安装",
  "Install failed": "安装失败",
  "Assets": "构建产物",
  "No release notes.": "没有发行说明。",
  "Release": "正式版",
  "Debug": "调试版",
  "unknown": "未知",

  "Confirm": "确认",
  "Cancel": "取消",
  "Keep": "保留",
  "Discard": "放弃",
  "Create": "创建",
  "New profile name": "新配置方案名称",
  "Sort by": "排序依据",
  "Frequency": "请求频率",
  "Most key requests first (default).": "密钥请求次数多的优先（默认）。",
  "Recently used": "最近使用",
  "Last requested first.": "最近请求的优先。",
  "Name": "名称",
  "Install time": "安装时间",
  "Newest installs first.": "最新安装的优先。",
  "Saved": "已保存",
  "Clear usage": "清除使用记录",
  "Create starter config": "创建初始配置",
  "The module seeds config.json on install. You can create a starter config now.": "模块安装时会初始化 config.json；现在也可以创建一份初始配置。",
  "Fix or remove the file on disk — the WebUI will not overwrite a config it cannot read.": "请修复或删除磁盘上的配置文件——WebUI 不会覆盖无法读取的配置。"
}));

const PATTERNS = [
  [/^(\d+) set$/, "$1 项已设置"],
  [/^(\d+) app$/, "$1 个应用"],
  [/^(\d+) apps$/, "$1 个应用"],
  [/^(\d+) auto$/, "$1 个自动包含"],
  [/^(\d+) to fix$/, "$1 项待修复"],
  [/^(\d+) issue to fix before saving$/, "保存前需修复 $1 项问题"],
  [/^(\d+) issues to fix before saving$/, "保存前需修复 $1 项问题"],
  [/^(\d+) issue to fix$/, "需修复 $1 项问题"],
  [/^(\d+) issues to fix$/, "需修复 $1 项问题"],
  [/^harvested → (.+)$/, "采集值 → $1"],
  [/^Delete selected \((\d+)\)$/, "删除已选（$1）"],
  [/^No keys match “(.+)”$/, "没有匹配“$1”的密钥"],
  [/^(\d+) real key hidden$/, "已隐藏 $1 个真实密钥"],
  [/^(\d+) real keys hidden$/, "已隐藏 $1 个真实密钥"],
  [/^(\d+) spoofed$/, "$1 个 TES 处理密钥"],
  [/^Remove (.+)$/, "移除 $1"],
  [/^Keybox validation failed: (.+)$/, "Keybox 校验失败：$1"],
  [/^Backend self-test failed: (.+)$/, "后端自检失败：$1"],
  [/^Last run: (.+)$/, "上次运行：$1"],
  [/^Import failed: (.+)$/, "导入失败：$1"],
  [/^Imported (.+) · EC-only$/, "已导入 $1 · 仅 EC"],
  [/^Imported (.+) · RSA-only$/, "已导入 $1 · 仅 RSA"],
  [/^Imported (.+) · RSA\+EC$/, "已导入 $1 · RSA+EC"],
  [/^Imported (.+)$/, "已导入 $1"],
  [/^Used by profile “(.+)”$/, "已由配置方案“$1”使用"],
  [/^(\d+) app · (\d+) auto$/, "$1 个手动应用 · $2 个自动应用"],
  [/^(\d+) apps · (\d+) auto$/, "$1 个手动应用 · $2 个自动应用"],
  [/^\+(\d+) more$/, "另有 $1 个"],
  [/^user (\d+)$/, "用户 $1"],
  [/^User (\d+)$/, "用户 $1"],
  [/^Show only user (\d+)$/, "仅显示用户 $1"],
  [/^Installed for user (\d+)$/, "已为用户 $1 安装"],
  [/^(\d+) key requests recorded$/, "记录到 $1 次密钥请求"],
  [/^Auto-include on — (\d+) app installed since TEESimulator started is also in scope\.$/, "已开启自动包含——TEESimulator 启动后安装的 $1 个应用也在作用范围内。"],
  [/^Auto-include on — (\d+) apps installed since TEESimulator started are also in scope\.$/, "已开启自动包含——TEESimulator 启动后安装的 $1 个应用也在作用范围内。"],
  [/^Scope — (.+)$/, "作用范围 — $1"],
  [/^Advanced: targets caller uid (\d+)$/, "高级：匹配调用方 UID $1"],
  [/^(.+) is not installed \(a name-match applies if it installs later\)$/, "$1 当前未安装（以后安装时仍会按名称匹配）"],
  [/^(.+) is not installed$/, "$1 当前未安装"],
  [/^No apps match “(.+)”$/, "没有匹配“$1”的应用"],
  [/^Inspect (.+)$/, "检查 $1"],
  [/^(\d+) cert$/, "$1 张证书"],
  [/^(\d+) certs$/, "$1 张证书"],
  [/^DeviceID: (.+)$/, "设备 ID：$1"],
  [/^Signing capabilities: EC-only$/, "签名能力：仅 EC"],
  [/^Signing capabilities: RSA-only$/, "签名能力：仅 RSA"],
  [/^Signing capabilities: RSA\+EC$/, "签名能力：RSA+EC"],
  [/^build (\d+)$/, "构建 $1"],
  [/^commit ([0-9a-f]+)$/, "提交 $1"],
  [/^release page ↗$/, "发行页面 ↗"],
  [/^Flashes (.+) over the current module, then reboot to apply\.$/, "将 $1 构建覆盖刷入当前模块，重启后生效。"],
  [/^Clear filter (.+)$/, "清除筛选 $1"],
  [/^Filter by (.+)$/, "按 $1 筛选"]
];

function translateString(value) {
  if (typeof value !== "string" || value === "") return value;
  const exact = EXACT.get(value);
  if (exact != null) return exact;
  for (const [re, replacement] of PATTERNS) {
    if (re.test(value)) return value.replace(re, replacement);
  }
  return value;
}

function translateTextNode(node) {
  const raw = node.nodeValue;
  if (!raw || !raw.trim()) return;
  const lead = raw.match(/^\s*/)?.[0] || "";
  const tail = raw.match(/\s*$/)?.[0] || "";
  const core = raw.slice(lead.length, raw.length - tail.length);
  const translated = translateString(core);
  if (translated !== core) node.nodeValue = lead + translated + tail;
}

function translateElement(el) {
  if (!(el instanceof Element)) return;
  for (const attr of ["placeholder", "aria-label", "title"]) {
    if (!el.hasAttribute(attr)) continue;
    const before = el.getAttribute(attr);
    const after = translateString(before);
    if (after !== before) el.setAttribute(attr, after);
  }
  for (const node of el.childNodes) {
    if (node.nodeType === Node.TEXT_NODE) translateTextNode(node);
  }
}

function translateTree(root) {
  if (root.nodeType === Node.TEXT_NODE) {
    translateTextNode(root);
    return;
  }
  if (!(root instanceof Element) && root !== document) return;
  if (root instanceof Element) translateElement(root);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    if (node.nodeType === Node.TEXT_NODE) translateTextNode(node);
    else translateElement(node);
  }
}

export function installZhCn() {
  document.documentElement.lang = "zh-CN";
  window.__TEESIM_LOCALE__ = "zh-CN";
  translateTree(document);

  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type === "characterData") {
        translateTextNode(m.target);
        continue;
      }
      if (m.type === "attributes") {
        translateElement(m.target);
        continue;
      }
      for (const node of m.addedNodes) translateTree(node);
    }
  });
  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: ["placeholder", "aria-label", "title"],
  });

  return observer;
}

export { translateString };
