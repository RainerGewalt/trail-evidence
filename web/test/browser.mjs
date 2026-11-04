#!/usr/bin/env node
// The browser verifier (web/) in headless Chrome: loads the page, clicks
// "the example journal" and "a tampered example", and checks what the page
// shows against the README: the example is VALID with 4 valid records, the
// tampered example INVALID with hash_mismatch on record #2 (2 errors, 3 valid
// and 1 invalid record). It also checks that the page made no request to
// another origin, sent nothing but GET requests, and threw no exception.
//
//   node web/test/browser.mjs          serve web/ of this checkout on a free
//                                      local port and check it (L4)
//   node web/test/browser.mjs <url>    check a deployed page, for example
//                                      https://rainergewalt.github.io/trail-evidence/ (L5)
//
// Needs Node 22 or newer (built-in WebSocket) and Chrome or Chromium; set
// CHROME to its path if it is not on PATH as google-chrome, chromium or
// chromium-browser. CHROME_PORT fixes the DevTools port (default: a free one
// chosen by Chrome). The Chrome profile and Chrome's temporary files go to a
// fresh directory under TMPDIR, which is removed afterwards; Chrome keeps a
// socket there, so TMPDIR must be short (about 50 characters at most).
//
// Exit 0: every check passed. 1: a check failed. 2: setup error (no Chrome,
// Node too old, page not reachable).

import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(HERE, "..");

// Safety net against a hang only; every wait below ends on an ordered signal
// (a DevTools line on stderr, a CDP response or event, a DOM mutation).
const HANG_MS = 60_000;

const CASES = [
  {
    name: "the example journal is VALID with 4 valid records",
    link: "load-example",
    file: "examples/transfer-worker.jsonl",
    label: "✓ VALID",
    verdict: "valid",
    records: 4,
    errors: 0,
    states: { valid: 4, invalid: 0, unknown: 0, outside_scope: 0 },
    findings: [],
  },
  {
    name: "the tampered example is INVALID with hash_mismatch on record #2",
    link: "load-tampered",
    file: "examples/tampered/hash-mismatch.jsonl",
    label: "✗ INVALID",
    verdict: "invalid",
    records: 4,
    errors: 2,
    states: { valid: 3, invalid: 1, unknown: 0, outside_scope: 0 },
    findings: [[2, "hash_mismatch"]],
  },
];

let failures = 0;
let checks = 0;

function check(cond, message, detail) {
  checks++;
  if (cond) {
    console.log("ok   " + message);
  } else {
    failures++;
    console.log("FAIL " + message + (detail ? "\n       " + detail : ""));
  }
}

function setupError(message) {
  console.error("browser: " + message);
  process.exit(2);
}

function withTimeout(promise, what) {
  let timer;
  const hang = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`no answer within ${HANG_MS / 1000} s: ${what}`)), HANG_MS);
  });
  return Promise.race([promise, hang]).finally(() => clearTimeout(timer));
}

function findChrome() {
  if (process.env.CHROME) return process.env.CHROME;
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    const r = spawnSync("sh", ["-c", `command -v ${name}`], { encoding: "utf8" });
    if (r.status === 0 && r.stdout.trim()) return r.stdout.trim();
  }
  return null;
}

// ---------------------------------------------------------------- local page

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".jsonl": "application/x-ndjson; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};

function serveWeb() {
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    let rel = decodeURIComponent(url.pathname);
    if (rel.endsWith("/")) rel += "index.html";
    const file = path.resolve(WEB, "." + rel);
    let ok = file.startsWith(WEB + path.sep) && !file.startsWith(path.join(WEB, "test") + path.sep);
    try {
      ok = ok && statSync(file).isFile();
    } catch {
      ok = false;
    }
    if (!ok) {
      res.writeHead(404).end("not found");
      return;
    }
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] || "application/octet-stream" });
    res.end(readFileSync(file));
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

// ---------------------------------------------------------------- Chrome

function startChrome(bin, base) {
  const profile = path.join(base, "profile");
  const tmp = path.join(base, "tmp");
  mkdirSync(tmp);
  const args = [
    "--headless=new",
    `--remote-debugging-port=${process.env.CHROME_PORT || 0}`,
    "--remote-debugging-address=127.0.0.1",
    `--user-data-dir=${profile}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-gpu",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
  ];
  // GitHub-hosted Ubuntu runners restrict the user namespaces Chrome's
  // sandbox needs. The page under test is this repository's own.
  if (process.env.CI) args.push("--no-sandbox");
  args.push("about:blank");
  // Chrome's own temporary files go to base/tmp, so that removing base
  // removes them too.
  const child = spawn(bin, args, { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, TMPDIR: tmp } });
  const exited = new Promise((resolve) => child.once("exit", resolve));
  const endpoint = new Promise((resolve, reject) => {
    let buf = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      buf += chunk;
      const m = buf.match(/DevTools listening on (ws:\/\/\S+)/);
      if (m) resolve(m[1]);
    });
    child.once("error", (err) => reject(new Error(`cannot start ${bin}: ${err.message}`)));
    child.once("exit", (code, signal) => {
      const hint = /Socket path too long/.test(buf) ? "\nChrome keeps a socket under TMPDIR; use a shorter TMPDIR." : "";
      reject(new Error(`${bin} exited (${code ?? signal}) before DevTools listened:\n${buf.slice(-2000)}${hint}`));
    });
  });
  return { child, exited, endpoint };
}

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Set();
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id !== undefined) {
        const p = this.pending.get(msg.id);
        if (!p) return;
        this.pending.delete(msg.id);
        if (msg.error) p.reject(new Error(`${p.method}: ${msg.error.message}`));
        else p.resolve(msg.result);
        return;
      }
      for (const fn of this.listeners) fn(msg);
    });
  }

  static connect(url) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.addEventListener("open", () => resolve(new CDP(ws)), { once: true });
      ws.addEventListener("error", () => reject(new Error(`cannot connect to ${url}`)), { once: true });
    });
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    const msg = { id, method, params };
    if (sessionId) msg.sessionId = sessionId;
    return withTimeout(new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      this.ws.send(JSON.stringify(msg));
    }), method);
  }

  // Resolves with the first event `method` of `sessionId` after the call.
  once(method, sessionId) {
    return new Promise((resolve) => {
      const fn = (msg) => {
        if (msg.method === method && msg.sessionId === sessionId) {
          this.listeners.delete(fn);
          resolve(msg.params);
        }
      };
      this.listeners.add(fn);
    });
  }

  on(fn) {
    this.listeners.add(fn);
  }

  close() {
    this.ws.close();
  }
}

// Runs in the page: clicks the link and resolves once the page has rendered
// its JSON report, the last thing render() writes (the MutationObserver
// fires after render() has finished, because render() is synchronous), or
// has reported that it could not load or verify.
const CLICK_AND_READ = `(async (linkId) => {
  const label = document.getElementById("verdict-label");
  const status = document.getElementById("status");
  const reportJson = document.getElementById("report-json");
  const failed = /^(Could not|Verification failed|The example cannot|This browser offers no WebCrypto)/;
  const done = new Promise((resolve) => {
    const look = () => {
      if (reportJson.textContent) resolve({ rendered: true });
      else if (failed.test(status.textContent)) resolve({ rendered: false, status: status.textContent });
    };
    new MutationObserver(look).observe(document.body, { subtree: true, childList: true, characterData: true });
    look();
  });
  document.getElementById(linkId).click();
  const r = await done;
  return Object.assign(r, {
    label: label.textContent,
    summary: document.getElementById("verdict-summary").textContent,
    report: reportJson.textContent,
  });
})`;

async function checkPage(cdp, pageUrl) {
  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
  const requests = [];
  const exceptions = [];
  cdp.on((msg) => {
    if (msg.sessionId !== sessionId) return;
    if (msg.method === "Network.requestWillBeSent") {
      requests.push({ url: msg.params.request.url, method: msg.params.request.method });
    } else if (msg.method === "Runtime.exceptionThrown") {
      const d = msg.params.exceptionDetails;
      exceptions.push((d.exception && d.exception.description) || d.text);
    }
  });
  await cdp.send("Page.enable", {}, sessionId);
  await cdp.send("Network.enable", {}, sessionId);
  await cdp.send("Runtime.enable", {}, sessionId);
  await cdp.send("Network.setCacheDisabled", { cacheDisabled: true }, sessionId);

  for (const c of CASES) {
    const loaded = cdp.once("Page.loadEventFired", sessionId);
    const nav = await cdp.send("Page.navigate", { url: pageUrl }, sessionId);
    if (nav.errorText) throw new Error(`cannot open ${pageUrl}: ${nav.errorText}`);
    await withTimeout(loaded, `load event of ${pageUrl}`);
    // A script that failed while the page loaded leaves the links dead.
    if (exceptions.length) {
      check(false, c.name, `the page threw while loading: ${exceptions.join("; ")}`);
      continue;
    }
    const res = await cdp.send("Runtime.evaluate", {
      expression: `${CLICK_AND_READ}(${JSON.stringify(c.link)})`,
      awaitPromise: true,
      returnByValue: true,
    }, sessionId);
    if (res.exceptionDetails) {
      check(false, c.name, `script error: ${res.exceptionDetails.text}`);
      continue;
    }
    const r = res.result.value;
    if (!r.rendered) {
      check(false, c.name, `no verdict; the page says: ${r.status}`);
      continue;
    }
    let report = null;
    try {
      report = JSON.parse(r.report);
    } catch {
      // reported below
    }
    const got = report && {
      label: r.label,
      verdict: report.verdict,
      records: report.records,
      errors: report.errors,
      states: report.states,
      findings: [...new Set(report.findings.map((f) => JSON.stringify([f.index, f.class])))].map((s) => JSON.parse(s)),
    };
    const want = { label: c.label, verdict: c.verdict, records: c.records, errors: c.errors, states: c.states, findings: c.findings };
    check(JSON.stringify(got) === JSON.stringify(want), c.name,
      `got:  ${JSON.stringify(got)}\n       want: ${JSON.stringify(want)}`);
    console.log(`       ${r.label}  ${r.summary}`);
  }

  const origin = new URL(pageUrl).origin;
  const fetched = requests.filter((q) => !q.url.startsWith("data:") && q.url !== "about:blank");
  const foreign = fetched.filter((q) => new URL(q.url).origin !== origin);
  check(foreign.length === 0, `the page requests nothing from another origin than ${origin}`,
    foreign.map((q) => q.url).join(", "));
  const notGet = fetched.filter((q) => q.method !== "GET");
  check(notGet.length === 0, "the page sends no request other than GET (nothing is uploaded)",
    notGet.map((q) => `${q.method} ${q.url}`).join(", "));
  for (const c of CASES) {
    const want = new URL(c.file, pageUrl).href;
    check(fetched.some((q) => q.url === want), `the page loads the bundled ${c.file}`);
  }
  check(exceptions.length === 0, "the page throws no exception", exceptions.join("; "));

  await cdp.send("Target.closeTarget", { targetId });
}

async function main() {
  const major = Number(process.versions.node.split(".")[0]);
  if (major < 22) setupError(`needs Node 22 or newer (built-in WebSocket), found ${process.versions.node}`);
  const arg = process.argv[2];
  if (arg === "-h" || arg === "--help") {
    console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(1, 23).map((l) => l.replace(/^\/\/ ?/, "")).join("\n"));
    return 0;
  }
  const bin = findChrome();
  if (!bin) setupError("Chrome or Chromium not found; set CHROME");

  let server = null;
  let pageUrl = arg;
  if (!pageUrl) {
    server = await serveWeb();
    pageUrl = `http://127.0.0.1:${server.address().port}/`;
  }
  if (!pageUrl.endsWith("/") && !pageUrl.endsWith(".html")) pageUrl += "/";
  console.log(`page:   ${pageUrl}${server ? " (web/ of this checkout)" : ""}`);

  const base = mkdtempSync(path.join(os.tmpdir(), "te-chrome-"));
  const chrome = startChrome(bin, base);
  let cdp = null;
  try {
    const ws = await withTimeout(chrome.endpoint, "Chrome DevTools endpoint");
    const version = spawnSync(bin, ["--version"], { encoding: "utf8" }).stdout.trim();
    console.log(`chrome: ${version} (pid ${chrome.child.pid})`);
    cdp = await CDP.connect(ws);
    await checkPage(cdp, pageUrl);
  } finally {
    // Browser.close shuts Chrome down cleanly, so that it removes its own
    // temporary files; SIGTERM only when that is not possible. The process
    // exit is the signal that it is done.
    const running = () => chrome.child.exitCode === null && chrome.child.signalCode === null;
    let closing = false;
    if (cdp) {
      closing = await cdp.send("Browser.close").then(() => true, () => false);
      cdp.close();
    }
    if (running() && !closing) chrome.child.kill("SIGTERM");
    if (running()) await withTimeout(chrome.exited, "Chrome exit").catch(() => chrome.child.kill("SIGKILL"));
    rmSync(base, { recursive: true, force: true });
    if (server) server.close();
  }
  console.log(failures ? `\n${failures} of ${checks} browser checks failed` : `\nall ${checks} browser checks passed`);
  return failures ? 1 : 0;
}

main().then((code) => process.exit(code), (err) => {
  console.error("browser: " + (err && err.stack ? err.stack : err));
  process.exit(2);
});
