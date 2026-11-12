/* Page logic for the Trail Evidence Verifier. All verification happens in
 * verify.js, in this tab; the only network requests this page ever makes are
 * the optional fetches of the two example journals that ship with the page.
 * The profile registry comes from profiles.js, loaded with the page. */
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
  const allowBox = $("allow-incomplete");
  const knownBox = $("require-known-profiles");
  const knownProfiles = $("known-profiles");
  const stateCounters = $("state-counters");
  const profileCounters = $("profile-counters");
  const recordFilter = $("record-filter");
  const recordsNote = $("records-note");
  const recordsBody = document.querySelector("#records tbody");
  const verifyButton = $("verify");
  const status = $("status");
  const result = $("result");
  const verdict = $("verdict");
  const verdictLabel = $("verdict-label");
  const verdictSummary = $("verdict-summary");
  const signatureNote = $("signature-note");
  const covChain = $("cov-chain");
  const covSignatures = $("cov-signatures");
  const covProfiles = $("cov-profiles");
  const covCompleteness = $("cov-completeness");
  const cryptoNote = $("crypto-note");
  const counters = $("counters");
  const streamsList = $("streams");
  const findingsList = $("findings");
  const noFindings = $("no-findings");
  const reportJson = $("report-json");
  const copyButton = $("copy-report");

  let journal = null; // { name, data }: data is bytes (Uint8Array) or dropped text
  let running = false;
  let lastReport = null;

  const MAX_ROWS = 2000;
  // State labels: colour is never the only cue, every badge carries text.
  const STATE_LABEL = { valid: "valid", invalid: "invalid", unknown: "unknown", outside_scope: "outside scope", none: "none" };
  const STATE_MARK = { valid: "\u2713", invalid: "\u2717", unknown: "?", outside_scope: "\u2013", none: "\u00b7" };

  // ---------------------------------------------------------------- input

  // The verifier gets the bytes of the file, not text decoded by the browser:
  // it decodes every line on its own and reports a line that is not UTF-8
  // (SPEC.md section 2), where file.text() would silently replace the bytes.
  const lenient = new TextDecoder("utf-8");
  function setJournal(name, data, note) {
    journal = { name, data };
    const text = typeof data === "string" ? data : lenient.decode(data);
    const lines = text.split("\n").filter((l) => l.replace(/[ \t\r]+/g, "") !== "").length;
    const size = typeof data === "string" ? new TextEncoder().encode(data).length : data.length;
    fileInfo.textContent = `${name} · ${formatBytes(size)} · ${lines} non-empty line(s)`;
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

  // A result on screen always belongs to the journal and key shown above it:
  // when the next check cannot run, the previous result goes away.
  function hideResult() {
    result.hidden = true;
    lastReport = null;
  }

  async function takeFile(file) {
    if (!file) return;
    let data;
    try {
      data = new Uint8Array(await file.arrayBuffer());
    } catch (err) {
      // A file that cannot be read gets no verdict (SPEC.md section 6.4).
      journal = null;
      hideResult();
      verifyButton.disabled = true;
      fileInfo.textContent = "";
      status.textContent = `Could not read ${file.name}, so there is no verdict: ${err.message}`;
      return;
    }
    setJournal(file.name, data);
  }

  fileInput.addEventListener("change", () => takeFile(fileInput.files[0]));

  dropzone.addEventListener("click", (ev) => {
    if (ev.target.closest("a, label")) return;
    fileInput.click();
  });
  dropzone.addEventListener("keydown", (ev) => {
    // Only keys on the drop zone itself open the file chooser; Enter on one
    // of the example links inside it follows that link.
    if (ev.target !== dropzone) return;
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
      setJournal(name, new Uint8Array(await res.arrayBuffer()), note);
    } catch (err) {
      hideResult();
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
  for (const box of [allowBox, knownBox]) box.addEventListener("change", () => { if (journal) run(); });
  recordFilter.addEventListener("change", () => { if (lastReport) renderRecords(lastReport); });

  // ---------------------------------------------------------------- run

  async function run() {
    if (!journal || running) return;
    const { key, ok } = currentKey();
    if (!ok) {
      hideResult();
      status.textContent = "Fix the public key or clear the field.";
      return;
    }
    if (!te.cryptoAvailable()) {
      hideResult();
      status.textContent = "This browser offers no WebCrypto here. Open the page over https, from localhost or as a local file.";
      return;
    }
    running = true;
    verifyButton.disabled = true;
    status.textContent = "Verifying…";
    try {
      const report = await te.verifyStream(journal.data, {
        publicKey: key,
        requireSignatures: !!key && requireBox.checked,
        allowIncomplete: allowBox.checked,
        requireKnownProfiles: knownBox.checked,
        onProgress: (n) => { status.textContent = `Verifying… ${n} records`; },
      });
      render(report, key !== null);
      status.textContent = "";
    } catch (err) {
      hideResult();
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

  function renderCoverage(report, keyGiven) {
    const c = te.coverage(report, keyGiven);
    covChain.textContent = c.chain;
    covSignatures.textContent = c.signatures;
    covProfiles.textContent = c.profiles;
    covCompleteness.textContent = c.completeness;
  }

  function render(report, keyGiven) {
    result.hidden = false;
    // incomplete keeps its own, non-green look even when it is allowed.
    verdict.className = "verdict " + report.verdict;
    verdictLabel.textContent = report.verdict === "incomplete"
      ? (report.ok ? "? INCOMPLETE (allowed)" : "? INCOMPLETE")
      : report.verdict === "valid" ? "\u2713 VALID" : "\u2717 INVALID";
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

    renderCoverage(report, keyGiven);

    // Counters
    stateCounters.replaceChildren();
    for (const st of te.STATES) stateCounters.appendChild(stateCounter(st, report.states[st]));
    profileCounters.replaceChildren();
    for (const st of te.PROFILE_STATES) profileCounters.appendChild(stateCounter(st, report.profile_states[st]));
    const counts = {};
    for (const f of report.findings) counts[f.class] = (counts[f.class] || 0) + 1;
    counters.replaceChildren();
    for (const cls of te.ERROR_CLASSES) counters.appendChild(counter(cls, counts[cls] || 0, "error"));
    for (const cls of te.NOTICE_CLASSES) counters.appendChild(counter(cls, counts[cls] || 0, "notice"));

    lastReport = report;
    renderRecords(report);

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
    noFindings.textContent = report.records === 0
      ? "No findings, because there is no record: nothing was checked."
      : "No findings. Every hash recomputes, every link and sequence number matches, every profile named was checked.";
    for (const f of report.findings) {
      const head = el("div", { class: "head" }, [
        el("span", { class: "cls", text: f.class }),
        el("span", { text: f.severity }),
        el("span", { text: `line ${f.line}` }),
        el("span", { text: `record #${f.index}` }),
        el("span", { text: f.stream_id === undefined || f.stream_id === null ? "stream -" : `stream ${JSON.stringify(f.stream_id)}` }),
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

  function stateCounter(state, n) {
    return el("li", { class: "state-count " + (n > 0 ? "hit " : "") + "st-" + state }, [
      el("span", { class: "count", text: String(n) }),
      el("span", { class: "label" }, [badgeText(state)]),
    ]);
  }

  function badgeText(state) {
    return `${STATE_MARK[state] || ""} ${STATE_LABEL[state] || state}`;
  }

  function badge(state) {
    return el("span", { class: "badge st-" + state, text: badgeText(state) });
  }

  function needsAttention(r) {
    return r.state !== "valid" || (r.profile_state !== "none" && r.profile_state !== "valid");
  }

  function renderRecords(report) {
    const rows = recordFilter.value === "attention" ? report.results.filter(needsAttention) : report.results;
    recordsBody.replaceChildren();
    for (const r of rows.slice(0, MAX_ROWS)) {
      recordsBody.appendChild(el("tr", { class: "row-" + r.state }, [
        el("td", { text: String(r.index) }),
        el("td", { text: String(r.line) }),
        el("td", { class: "mono", text: r.stream_id === null || r.stream_id === undefined ? "-" : r.stream_id }),
        el("td", { class: "mono", text: r.seq === null || r.seq === undefined ? "-" : String(r.seq) }),
        el("td", null, [badge(r.state)]),
        el("td", { class: "mono", text: r.profile || "-" }),
        el("td", null, [badge(r.profile_state)]),
      ]));
    }
    const notes = [];
    if (recordFilter.value === "attention") notes.push("Records that are not valid, or whose profile failed or was not checked.");
    if (rows.length === 0) notes.push(recordFilter.value === "attention" ? "None: every record is valid and every profile was checked." : "No records.");
    if (rows.length > MAX_ROWS) notes.push(`Showing the first ${MAX_ROWS} of ${rows.length} rows; the JSON report below has all of them.`);
    recordsNote.textContent = notes.join(" ");
    recordsNote.hidden = notes.length === 0;
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
  const ids = te.profiles();
  knownProfiles.textContent = ids.length
    ? `Profiles this page checks: ${ids.join(", ")}. Records with any other profile get the profile state outside_scope.`
    : "No profile registry loaded (profiles.js is missing): every profile is reported as outside_scope.";
  currentKey();
})();
