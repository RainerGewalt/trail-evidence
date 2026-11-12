#!/usr/bin/env node
// Browser check of the verifier page (level L4 in docs/TESTING.md): the real
// page in headless Chrome, driven over the DevTools protocol with real key
// and file-input events. Node 22 or newer (built-in WebSocket), Chrome or
// Chromium; no other dependencies. Runs in CI (job web-browser) and by hand
// before a tag:
//
//   node web/test/browser.mjs                       the checks
//   node web/test/browser.mjs --screenshots docs/screenshots
//                                                   and the README screenshots
//
// It serves web/ on 127.0.0.1:$TE_HTTP_PORT (default 15080), starts $CHROME
// (default google-chrome) with remote debugging on $TE_CDP_PORT (default
// 15222) and checks: Tab to each example link and Enter loads the example and
// opens no file chooser; Enter on the drop zone opens it; an empty file, a
// file that is not JSON and a file with a line that is not UTF-8 get a verdict
// that is not green and a coverage text that says what was checked; an
// invalid public key hides the previous result. Exit 0 when every check
// passes.
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, copyFileSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = process.argv.slice(2);
const webDir = path.join(ROOT, "web");
const shotsAt = args.indexOf("--screenshots");
const shots = shotsAt >= 0 ? path.resolve(args[shotsAt + 1]) : null;
const HTTP_PORT = Number(process.env.TE_HTTP_PORT || 15080);
const CDP_PORT = Number(process.env.TE_CDP_PORT || 15222);
const CHROME = process.env.CHROME || "google-chrome";

let failures = 0;
const ok = (m) => console.log("ok   " + m);
const fail = (m) => { failures++; console.log("FAIL " + m); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".jsonl": "text/plain", ".svg": "image/svg+xml" };
const server = createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const p = path.join(webDir, decodeURIComponent(url.pathname === "/" ? "/index.html" : url.pathname));
  if (!p.startsWith(webDir) || !existsSync(p) || statSync(p).isDirectory()) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { "content-type": types[path.extname(p)] || "application/octet-stream" });
  res.end(readFileSync(p));
});
await new Promise((r) => server.listen(HTTP_PORT, "127.0.0.1", r));

const work = mkdtempSync(path.join(tmpdir(), "te-browser-"));
const profile = path.join(work, "chrome-profile");
// The files of the file-input checks.
const cases = path.join(work, "cases");
mkdirSync(cases);
writeFileSync(path.join(cases, "empty.jsonl"), "");
writeFileSync(path.join(cases, "not-json.jsonl"), "this is not json\n");
copyFileSync(path.join(ROOT, "testdata", "streams", "invalid-utf8-in-string.jsonl"), path.join(cases, "invalid-utf8.jsonl"));
const chrome = spawn(CHROME, ["--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-gpu",
  `--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${profile}`, "--window-size=1200,900", "about:blank"], { stdio: "ignore", env: chromeEnv() });

// Chrome puts a Unix socket into TMPDIR, whose path must stay short.
function chromeEnv() {
  const env = { ...process.env };
  delete env.TMPDIR;
  return env;
}

async function cdpTarget() {
  for (let i = 0; i < 100; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`)).json();
      const page = list.find((t) => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch (err) { /* not up yet */ }
    await sleep(100);
  }
  throw new Error("Chrome did not start");
}

const ws = new WebSocket(await cdpTarget());
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let nextId = 1;
const pending = new Map();
const events = [];
ws.addEventListener("message", (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) reject(new Error(msg.error.message)); else resolve(msg.result);
  } else if (msg.method) {
    events.push(msg);
  }
});
const send = (method, params = {}) => new Promise((resolve, reject) => {
  const id = nextId++;
  pending.set(id, { resolve, reject });
  ws.send(JSON.stringify({ id, method, params }));
});
const evaluate = async (expr) => (await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true })).result.value;
async function waitFor(expr, ms = 5000) {
  for (let t = 0; t < ms; t += 50) {
    if (await evaluate(expr)) return true;
    await sleep(50);
  }
  return false;
}
async function key(k, code, vk, text) {
  await send("Input.dispatchKeyEvent", { type: "keyDown", key: k, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, text });
  await send("Input.dispatchKeyEvent", { type: "keyUp", key: k, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk });
}
async function load() {
  events.length = 0;
  await send("Page.navigate", { url: `http://127.0.0.1:${HTTP_PORT}/index.html` });
  await waitFor("document.readyState === 'complete' && !!window.TrailEvidence");
}
const chooserOpened = () => events.some((e) => e.method === "Page.fileChooserOpened");
const state = () => evaluate(`({ hidden: document.getElementById("result").hidden, label: document.getElementById("verdict-label").textContent,
  info: document.getElementById("file-info").textContent, chain: document.getElementById("cov-chain").textContent,
  status: document.getElementById("status").textContent, nofind: document.getElementById("no-findings").textContent })`);

try {
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Page.setInterceptFileChooserDialog", { enabled: true });
  await send("Emulation.setDeviceMetricsOverride", { width: 1200, height: 900, deviceScaleFactor: 1, mobile: false });

  // Keyboard: Tab to each example link, press Enter.
  for (const [id, file, label] of [["load-example", "transfer-worker.jsonl", "\u2713 VALID"], ["load-tampered", "hash-mismatch.jsonl", "\u2717 INVALID"]]) {
    await load();
    let focused = false;
    for (let i = 0; i < 30 && !focused; i++) {
      await key("Tab", "Tab", 9);
      focused = await evaluate(`document.activeElement && document.activeElement.id === ${JSON.stringify(id)}`);
    }
    if (!focused) { fail(`Tab does not reach #${id}`); continue; }
    await key("Enter", "Enter", 13, "\r");
    const loaded = await waitFor(`!document.getElementById("result").hidden && document.getElementById("file-info").textContent.includes(${JSON.stringify(file)})`, 4000);
    const s = await state();
    if (loaded && s.label === label && !chooserOpened()) ok(`Tab to #${id}, Enter: ${file} loaded, verdict ${s.label}, no file chooser`);
    else fail(`Tab to #${id}, Enter: loaded=${loaded} label=${JSON.stringify(s.label)} fileChooserOpened=${chooserOpened()} info=${JSON.stringify(s.info)}`);
  }

  // Enter on the drop zone itself still opens the file chooser.
  await load();
  await evaluate(`document.getElementById("dropzone").focus()`);
  await key("Enter", "Enter", 13, "\r");
  await sleep(300);
  if (chooserOpened()) ok("Enter on the drop zone opens the file chooser");
  else fail("Enter on the drop zone does not open the file chooser");

  // Files through the file input.
  {
    const doc = await send("DOM.getDocument", {});
    const input = await send("DOM.querySelector", { nodeId: doc.root.nodeId, selector: "#file-input" });
    for (const [file, wantLabel, wantChain] of [
      ["empty.jsonl", "? INCOMPLETE", "no record"],
      ["not-json.jsonl", "\u2717 INVALID", "not a readable record"],
      ["invalid-utf8.jsonl", "\u2717 INVALID", ""],
    ]) {
      const p = path.join(cases, file);
      if (!existsSync(p)) { fail(`missing case ${p}`); continue; }
      await send("DOM.setFileInputFiles", { nodeId: input.nodeId, files: [p] });
      const shown = await waitFor(`!document.getElementById("result").hidden && document.getElementById("file-info").textContent.includes(${JSON.stringify(file)})`, 4000);
      const s = await state();
      if (shown && s.label === wantLabel && s.chain.includes(wantChain)) ok(`${file}: verdict ${s.label}; chain row: ${s.chain}`);
      else fail(`${file}: shown=${shown} label=${JSON.stringify(s.label)} chain=${JSON.stringify(s.chain)}`);
      if (file === "empty.jsonl") {
        const nf = s.nofind;
        if (!/Every hash recomputes/.test(nf)) ok(`${file}: the no-findings line does not claim that hashes were checked (${JSON.stringify(nf)})`);
        else fail(`${file}: no-findings line claims a check: ${JSON.stringify(nf)}`);
      }
    }
  }

  // An invalid public key blocks the check and hides the previous result.
  await load();
  await evaluate(`document.getElementById("load-example").click()`);
  await waitFor(`!document.getElementById("result").hidden`, 4000);
  await evaluate(`(() => { const k = document.getElementById("pubkey"); k.value = "abc"; k.dispatchEvent(new Event("input")); document.getElementById("verify").click(); })()`);
  await sleep(300);
  const s = await state();
  if (s.hidden && /public key/.test(s.status)) ok(`invalid key: previous result hidden, status ${JSON.stringify(s.status)}`);
  else fail(`invalid key: result hidden=${s.hidden}, status ${JSON.stringify(s.status)}`);

  if (shots) {
    // The two README screenshots of the tampered example, 930 CSS pixels wide
    // at scale 2: the page down to the record counters (verdict and what it
    // covers), and the records, streams and findings.
    await send("Emulation.setDeviceMetricsOverride", { width: 930, height: 1000, deviceScaleFactor: 2, mobile: false });
    await load();
    await evaluate(`document.getElementById("load-tampered").click()`);
    await waitFor(`!document.getElementById("result").hidden`, 4000);
    // The page scrolls to the result smoothly; wait for that, then measure
    // from the top of the page without a scrollbar.
    await send("Emulation.setScrollbarsHidden", { hidden: true });
    await sleep(1500);
    // A viewport as tall as the page, so that the capture needs no scrolling
    // and the layout it measures is the layout it captures.
    const height = await evaluate(`document.documentElement.scrollHeight`);
    await send("Emulation.setDeviceMetricsOverride", { width: 930, height, deviceScaleFactor: 2, mobile: false });
    await evaluate(`window.scrollTo({ top: 0, behavior: "instant" })`);
    await sleep(500);
    const clips = await evaluate(`(() => {
      const top = (el) => el.getBoundingClientRect().top + window.scrollY;
      const bottom = (el) => el.getBoundingClientRect().bottom + window.scrollY;
      const records = Array.from(document.querySelectorAll("h2")).find((h) => h.textContent === "Records");
      const w = window.innerWidth;
      return {
        verdict: { x: 0, y: 0, width: w, height: bottom(document.getElementById("state-counters")) + 16 },
        findings: { x: 0, y: top(records) - 20, width: w, height: bottom(document.getElementById("findings")) - top(records) + 40 },
      };
    })()`);
    for (const [name, clip] of [["browser-verifier-invalid.png", clips.verdict], ["browser-verifier-findings.png", clips.findings]]) {
      const res = await send("Page.captureScreenshot", { format: "png", clip: { ...clip, scale: 1 } });
      writeFileSync(path.join(shots, name), Buffer.from(res.data, "base64"));
      ok(`screenshot ${path.join(shots, name)}, ${Math.round(clip.width)}x${Math.round(clip.height)} CSS pixels at scale 2`);
    }
  }
} catch (err) {
  fail(String(err && err.stack || err));
} finally {
  try { ws.close(); } catch (err) { /* closed */ }
  chrome.kill();
  server.close();
  await sleep(300);
  rmSync(work, { recursive: true, force: true });
}
console.log(failures ? `\n${failures} browser check(s) failed` : "\nall browser checks passed");
process.exit(failures ? 1 : 0);
