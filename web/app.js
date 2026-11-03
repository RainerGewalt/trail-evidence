/* Page logic for the Trail Evidence Verifier. All verification happens in
 * verify.js, in this tab; the only network requests this page ever makes are
 * the optional fetches of the two example journals that ship with the page. */
(function () {
  "use strict";

  const te = window.TrailEvidence;
  const $ = (id) => document.getElementById(id);

  const dropzone = $("dropzone");
  const fileInput = $("file-input");
  const fileInfo = $("file-info");
  const loadExample = $("load-example");
  const loadTampered = $("load-tampered");
  const fileNote = $("file-note");
  const pubkeyInput = $("pubkey");
  const pubkeyError = $("pubkey-error");
  const requireBox = $("require-signatures");
  const verifyButton = $("verify");
  const status = $("status");
  const result = $("result");
  const verdict = $("verdict");
  const verdictLabel = $("verdict-label");
  const verdictSummary = $("verdict-summary");
  const signatureNote = $("signature-note");
  const cryptoNote = $("crypto-note");
  const counters = $("counters");
  const streamsList = $("streams");
  const findingsList = $("findings");
  const noFindings = $("no-findings");
  const reportJson = $("report-json");
  const copyButton = $("copy-report");

  let journal = null; // { name, text }
  let running = false;

  // ---------------------------------------------------------------- input

  function setJournal(name, text, note) {
    journal = { name, text };
    const lines = text.split("\n").filter((l) => l.trim() !== "").length;
    fileInfo.textContent = `${name} · ${formatBytes(text.length)} · ${lines} non-empty line(s)`;
    fileNote.textContent = note || "";
    fileNote.hidden = !note;
    verifyButton.disabled = false;
    status.textContent = "";
    run();
  }

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  }

  async function takeFile(file) {
    if (!file) return;
    try {
      const text = await file.text();
      setJournal(file.name, text);
    } catch (err) {
      status.textContent = `Could not read ${file.name}: ${err.message}`;
    }
  }

  fileInput.addEventListener("change", () => takeFile(fileInput.files[0]));

  dropzone.addEventListener("click", (ev) => {
    if (ev.target.closest("a, label")) return;
    fileInput.click();
  });
  dropzone.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      fileInput.click();
    }
  });
  for (const type of ["dragenter", "dragover"]) {
    dropzone.addEventListener(type, (ev) => {
      ev.preventDefault();
      dropzone.classList.add("dragover");
    });
  }
  for (const type of ["dragleave", "drop"]) {
    dropzone.addEventListener(type, (ev) => {
      ev.preventDefault();
      dropzone.classList.remove("dragover");
    });
  }
  dropzone.addEventListener("drop", (ev) => {
    const file = ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0];
    if (file) {
      takeFile(file);
      return;
    }
    const text = ev.dataTransfer && ev.dataTransfer.getData("text/plain");
    if (text) setJournal("dropped text", text);
  });
  // Dropping anywhere else must not navigate away from the page.
  window.addEventListener("dragover", (ev) => ev.preventDefault());
  window.addEventListener("drop", (ev) => ev.preventDefault());

  // Both bundled journals ship with the page under examples/.
  async function loadBundled(name, note) {
    status.textContent = "Loading example…";
    try {
      const res = await fetch(name, { cache: "no-cache" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setJournal(name, await res.text(), note);
    } catch (err) {
      status.textContent = window.location.protocol === "file:"
        ? `The example cannot be fetched from a file:// page; drop ${name} from the repository instead.`
        : `Could not load the example: ${err.message}`;
    }
  }

  loadExample.addEventListener("click", (ev) => {
    ev.preventDefault();
    loadBundled("examples/transfer-worker.jsonl",
      "Four transfer job results from one worker, chained and unchanged. Record #2 is a failed job.");
  });

  loadTampered.addEventListener("click", (ev) => {
    ev.preventDefault();
    loadBundled("examples/tampered/hash-mismatch.jsonl",
      "The same journal after someone edited record #2 to turn the failed job into a successful one, " +
      "without recomputing its hashes. The repository has one tampered copy per error class in examples/tampered/.");
  });

  // ---------------------------------------------------------------- key

  function currentKey() {
    const text = pubkeyInput.value.trim();
    pubkeyError.textContent = "";
    if (text === "") {
      requireBox.disabled = true;
      requireBox.checked = false;
      return { key: null, ok: true };
    }
    try {
      const key = te.parsePublicKey(text);
      requireBox.disabled = false;
      return { key, ok: true };
    } catch (err) {
      pubkeyError.textContent = err.message;
      requireBox.disabled = true;
      requireBox.checked = false;
      return { key: null, ok: false };
    }
  }

  pubkeyInput.addEventListener("input", currentKey);
  pubkeyInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !verifyButton.disabled) run();
  });
  verifyButton.addEventListener("click", run);

  // ---------------------------------------------------------------- run

  async function run() {
    if (!journal || running) return;
    const { key, ok } = currentKey();
    if (!ok) {
      status.textContent = "Fix the public key or clear the field.";
      return;
    }
    if (!te.cryptoAvailable()) {
      status.textContent = "This browser offers no WebCrypto here. Open the page over https, from localhost or as a local file.";
      return;
    }
    running = true;
    verifyButton.disabled = true;
    status.textContent = "Verifying…";
    try {
      const report = await te.verifyStream(journal.text, {
        publicKey: key,
        requireSignatures: !!key && requireBox.checked,
        onProgress: (n) => { status.textContent = `Verifying… ${n} records`; },
      });
      render(report, key !== null);
      status.textContent = "";
    } catch (err) {
      status.textContent = `Verification failed to run: ${err.message}`;
    } finally {
      running = false;
      verifyButton.disabled = false;
    }
  }

  // ---------------------------------------------------------------- output

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (k === "class") node.className = v;
        else if (k === "text") node.textContent = v;
        else node.setAttribute(k, v);
      }
    }
    for (const child of children || []) {
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  function render(report, keyGiven) {
    result.hidden = false;
    verdict.className = "verdict " + (report.ok ? "ok" : "fail");
    verdictLabel.textContent = report.ok ? "OK" : "FAIL";
    verdictSummary.textContent = te.summary(report);

    // Signature status
    signatureNote.hidden = true;
    cryptoNote.hidden = true;
    if (report.signature_check === "unavailable") {
      cryptoNote.hidden = false;
      cryptoNote.textContent = `Signatures not checked: this browser's WebCrypto has no Ed25519. ${report.signed_records} signed record(s) were counted but not verified; use the Go or Python verifier, or a current Chrome, Firefox or Safari.`;
    } else if (!keyGiven && report.signed_records > 0) {
      signatureNote.hidden = false;
      signatureNote.textContent = `${report.signed_records} record(s) carry a signature that was not checked. Enter the producer's public key to verify them.`;
    } else if (keyGiven && report.unsigned_records > 0 && !requireBox.checked) {
      signatureNote.hidden = false;
      signatureNote.textContent = `${report.unsigned_records} record(s) carry no signature. Tick "Require a signature on every record" to report them as signature_invalid.`;
    }

    // Counters
    const counts = {};
    for (const f of report.findings) counts[f.class] = (counts[f.class] || 0) + 1;
    counters.replaceChildren();
    for (const cls of te.ERROR_CLASSES) counters.appendChild(counter(cls, counts[cls] || 0, "error"));
    for (const cls of te.NOTICE_CLASSES) counters.appendChild(counter(cls, counts[cls] || 0, "notice"));

    // Streams
    streamsList.replaceChildren();
    for (const s of report.streams) {
      const dl = el("dl", null, [
        el("dt", { text: "stream_id" }), el("dd", { text: s.stream_id }),
        el("dt", { text: "records" }), el("dd", { text: String(s.records) }),
        el("dt", { text: "seq" }), el("dd", { text: `${s.first_seq} … ${s.last_seq}` }),
        el("dt", { text: "restarts" }), el("dd", { text: String(s.restarts) }),
        el("dt", { text: "last chain_hash" }), el("dd", { text: s.last_chain_hash }),
      ]);
      streamsList.appendChild(el("li", null, [dl]));
    }
    if (report.streams.length === 0) {
      streamsList.appendChild(el("li", { class: "muted", text: "No decodable record, so no stream." }));
    }

    // Findings
    findingsList.replaceChildren();
    noFindings.hidden = report.findings.length > 0;
    for (const f of report.findings) {
      const head = el("div", { class: "head" }, [
        el("span", { class: "cls", text: f.class }),
        el("span", { text: f.severity }),
        el("span", { text: `line ${f.line}` }),
        el("span", { text: `record #${f.index}` }),
        el("span", { text: f.stream_id === undefined ? "stream -" : `stream ${JSON.stringify(f.stream_id)}` }),
        el("span", { text: f.seq === undefined || f.seq === null ? "seq -" : `seq ${f.seq}` }),
      ]);
      findingsList.appendChild(el("li", { class: f.severity }, [head, el("p", { class: "msg", text: f.message })]));
    }

    reportJson.textContent = JSON.stringify(te.reportToJSON(report), null, 2);
    result.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function counter(cls, n, severity) {
    return el("li", { class: (n > 0 ? "hit " : "") + severity }, [
      el("span", { class: "count", text: String(n) }),
      el("span", { class: "label", text: cls }),
    ]);
  }

  copyButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(reportJson.textContent);
      copyButton.textContent = "Copied";
      setTimeout(() => { copyButton.textContent = "Copy"; }, 1500);
    } catch (err) {
      copyButton.textContent = "Copy failed";
    }
  });

  // ---------------------------------------------------------------- startup

  if (!te.cryptoAvailable()) {
    status.textContent = "This browser offers no WebCrypto here. Open the page over https, from localhost or as a local file.";
  }
  currentKey();
})();
