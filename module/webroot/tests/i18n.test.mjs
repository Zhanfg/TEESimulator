import test from "node:test";
import assert from "node:assert/strict";

const { translateString } = await import("../js/i18n/zh-cn.js");

test("zh-CN exact UI strings", () => {
  assert.equal(translateString("Profiles"), "配置方案");
  assert.equal(translateString("StrongBox"), "StrongBox");
  assert.equal(translateString("hardware"), "硬件（严格）");
  assert.equal(translateString("Run this"), "Run this");
});

test("zh-CN dynamic counters", () => {
  assert.equal(translateString("3 apps"), "3 个应用");
  assert.equal(translateString("2 issues to fix before saving"), "保存前需修复 2 项问题");
  assert.equal(translateString("Delete selected (4)"), "删除已选（4）");
  assert.equal(translateString("+7 more"), "另有 7 个");
});

test("zh-CN dynamic hardware text", () => {
  assert.equal(translateString("harvested → 202610"), "采集值 → 202610");
  assert.equal(
    translateString("Flashes release over the current module, then reboot to apply."),
    "将 release 构建覆盖刷入当前模块，重启后生效。",
  );
});
