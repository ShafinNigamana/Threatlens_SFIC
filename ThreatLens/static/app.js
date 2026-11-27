/* ==========================================================================
   ThreatLens — Frontend Controller (Offline-First, Zero External Dependencies)
   Matches Flask API Contract:
     GET  /api/status
     POST /api/upload?ai=true|false   (FormData 'logfile' OR JSON {content, filename})
     GET  /api/export/csv
     GET  /api/export/pdf
   ========================================================================== */

let currentFile = null;
let analysisData = null;
let currentFilter = "all";
let currentRingFilter = "all";
let scanMode = "auto"; // "auto" | "offline"

const SEV_EMOJI = { critical: "🔴", high: "🟠", medium: "🟡", low: "🟢" };

// Built-in Demo ProcMon CSV (matches app.cpp + hack.cpp + Ring 0 driver drop)
const SAMPLE_PROCMON_CSV = `"Time of Day","Process Name","PID","Operation","Path","Result","Detail"
"10:23:00.1120000","app.exe","4832","Process Start","","SUCCESS","Parent PID: 1200, Command line: app.exe"
"10:23:00.8901200","watchdog.exe","5104","OpenProcess","","SUCCESS","PID: 4832, Access: PROCESS_VM_READ"
"10:23:01.1050000","hack.exe","2048","OpenProcess","","SUCCESS","PID: 4832, Access: PROCESS_VM_WRITE | PROCESS_VM_OPERATION"
"10:23:01.4450322","hack.exe","2048","WriteProcessMemory","","SUCCESS","Target PID: 4832, Address: 0x0070FE48, Length: 4"
"10:23:01.6204100","unknown_loader.exe","3312","CreateFile","C:\\Windows\\System32\\drivers\\rootkit_drv.sys","SUCCESS","Desired Access: Generic Write"
"10:23:01.8901120","unknown_loader.exe","3312","RegSetValue","HKLM\\SYSTEM\\CurrentControlSet\\Services\\RootkitDrv\\ImagePath","SUCCESS","Type: REG_SZ, Data: \\??\\C:\\Windows\\System32\\drivers\\rootkit_drv.sys"
"10:23:02.1023300","unknown_loader.exe","3312","NtLoadDriver","\\Registry\\Machine\\System\\CurrentControlSet\\Services\\RootkitDrv","SUCCESS","Kernel driver load requested"
"10:23:02.4500000","powershell.exe","6190","RegSetValue","HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater","SUCCESS","Data: C:\\Users\\Public\\Temp\\payload.exe"
"10:23:02.9800000","certutil.exe","7012","CreateFile","C:\\Users\\Student\\AppData\\Local\\Temp\\drop.exe","SUCCESS","Desired Access: Generic Write"`;

// ── Init: Check backend & internet status ────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  checkStatus();
  setupDropZone();
});

async function checkStatus() {
  const badge = document.getElementById("statusBadge");
  const autoBtn = document.getElementById("modeAutoBtn");
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    if (data.online && data.has_api_key) {
      badge.innerHTML = '<span class="dot online"></span><span>Online • AI-Enhanced Ready</span>';
      if (autoBtn) autoBtn.style.display = "";
    } else if (data.online) {
      badge.innerHTML = '<span class="dot warn"></span><span>🔒 Data Privacy Mode (No API Key)</span>';
      if (autoBtn) autoBtn.style.display = "none";
      setScanMode("offline");
    } else {
      badge.innerHTML = '<span class="dot offline"></span><span>🔒 Data Privacy Mode (Offline)</span>';
      if (autoBtn) autoBtn.style.display = "none";
      setScanMode("offline");
    }
  } catch {
    badge.innerHTML = '<span class="dot offline"></span><span>🔒 Data Privacy Mode (Offline)</span>';
    if (autoBtn) autoBtn.style.display = "none";
    setScanMode("offline");
  }
}

// ── Mode Toggle (Auto AI vs Force Offline) ───────────────────────────────
function setScanMode(mode) {
  scanMode = mode;
  document.getElementById("modeAutoBtn").classList.toggle("active", mode === "auto");
  document.getElementById("modeOfflineBtn").classList.toggle("active", mode === "offline");
}

// ── Drag & Drop + File Input ─────────────────────────────────────────────
function setupDropZone() {
  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("fileInput");

  ["dragenter", "dragover"].forEach((evt) => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.add("drag-over");
    });
  });

  ["dragleave", "drop"].forEach((evt) => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.remove("drag-over");
    });
  });

  dropZone.addEventListener("drop", (e) => {
    if (e.dataTransfer.files.length > 0) handleFile(e.dataTransfer.files[0]);
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) handleFile(e.target.files[0]);
  });
}

function handleFile(file) {
  if (!file.name.toLowerCase().endsWith(".csv")) {
    alert("Please upload a .CSV file exported from Sysinternals ProcMon.");
    return;
  }
  currentFile = file;
  document.getElementById("fileName").textContent = file.name;
  document.getElementById("fileSize").textContent = formatBytes(file.size);
  document.getElementById("fileInfo").classList.remove("hidden");
  document.getElementById("analyzeBtn").disabled = false;
}

function clearFile() {
  currentFile = null;
  document.getElementById("fileInput").value = "";
  document.getElementById("fileInfo").classList.add("hidden");
  document.getElementById("analyzeBtn").disabled = true;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

// ── Analyze Uploaded File OR Built-in Sample ─────────────────────────────
async function analyzeFile() {
  if (!currentFile) return;
  const formData = new FormData();
  formData.append("logfile", currentFile);
  await runAnalysisRequest({ method: "POST", body: formData });
}

async function runSampleDemo() {
  await runAnalysisRequest({
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      filename: "sample_procmon_attack_capture.csv",
      content: SAMPLE_PROCMON_CSV,
    }),
  });
}

async function runAnalysisRequest(fetchOptions) {
  showScreen("loading");
  setStep(1);

  const aiFlag = scanMode === "auto" ? "true" : "false";
  try {
    setTimeout(() => setStep(2), 250);
    setTimeout(() => setStep(3), 550);

    const res = await fetch(`/api/upload?ai=${aiFlag}`, fetchOptions);
    const data = await res.json();

    if (!res.ok || data.error) {
      alert(data.error || "Analysis failed.");
      showScreen("upload");
      return;
    }

    setStep(4);
    analysisData = data;
    setTimeout(() => renderResults(data), 250);
  } catch (err) {
    alert(`Cannot reach ThreatLens backend: ${err.message}`);
    showScreen("upload");
  }
}

function setStep(activeStep) {
  for (let i = 1; i <= 4; i++) {
    const el = document.getElementById(`step${i}`);
    el.classList.remove("active", "done");
    if (i < activeStep) el.classList.add("done");
    else if (i === activeStep) el.classList.add("active");
  }
}

function showScreen(name) {
  document.getElementById("uploadScreen").classList.toggle("hidden", name !== "upload");
  document.getElementById("loadingScreen").classList.toggle("hidden", name !== "loading");
  document.getElementById("resultsScreen").classList.toggle("hidden", name !== "results");
  document.getElementById("exportButtons").classList.toggle("hidden", name !== "results");
}

// ── Render Results Dashboard ─────────────────────────────────────────────
function renderResults(data) {
  showScreen("results");

  const modeLabel = data.mode === "ai_enhanced"
    ? "🟢 AI-Enhanced (Gemini LLM + Local Rules)"
    : "🔒 Data Privacy Mode (100% Local Python Pattern & Reasoning Engine)";
  document.getElementById("resultsMeta").textContent =
    `${data.filename} • ${data.total_entries.toLocaleString()} events scanned in ${data.scan_time} • ${modeLabel}`;

  document.getElementById("statCritical").textContent = data.summary.critical;
  document.getElementById("statHigh").textContent = data.summary.high;
  document.getElementById("statMedium").textContent = data.summary.medium;
  document.getElementById("statLow").textContent = data.summary.low;

  const aiSec = document.getElementById("aiSection");
  const aiTitle = aiSec.querySelector(".ai-title");
  if (data.ai_result) {
    aiSec.classList.remove("hidden");
    aiTitle.textContent = data.mode === "ai_enhanced"
      ? "🤖 Gemini AI Threat Contextualization"
      : "🔒 Local Python Reasoning (Data Privacy Mode — LLM Disabled)";
    document.getElementById("aiRiskBadge").textContent =
      `Risk ${data.ai_result.risk_score ?? "?"}/100 — ${data.ai_result.risk_label || "Assessed"}`;
    document.getElementById("aiAnalysis").textContent = data.ai_result.ai_analysis || "";

    const chainWrap = document.getElementById("aiChain");
    if (data.ai_result.attack_chain) {
      chainWrap.classList.remove("hidden");
      document.getElementById("aiChainText").textContent = data.ai_result.attack_chain;
    } else {
      chainWrap.classList.add("hidden");
    }

    const recsWrap = document.getElementById("aiRecs");
    const recsList = document.getElementById("aiRecsList");
    recsList.innerHTML = "";
    if (Array.isArray(data.ai_result.recommendations) && data.ai_result.recommendations.length) {
      recsWrap.classList.remove("hidden");
      data.ai_result.recommendations.forEach((r) => {
        const li = document.createElement("li");
        li.textContent = r;
        recsList.appendChild(li);
      });
    } else {
      recsWrap.classList.add("hidden");
    }
  } else {
    aiSec.classList.add("hidden");
  }

  currentFilter = "all";
  currentRingFilter = "all";
  document.getElementById("searchBox").value = "";
  updateFilterButtons();
  renderTimeline();
}

function filterThreats(sev) {
  currentFilter = sev;
  updateFilterButtons();
  renderTimeline();
}

function filterRing(ring) {
  currentRingFilter = ring;
  updateFilterButtons();
  renderTimeline();
}

function updateFilterButtons() {
  document.querySelectorAll("[data-filter]").forEach((b) => {
    b.classList.toggle("active", b.dataset.filter === currentFilter);
  });
  document.querySelectorAll("[data-ring]").forEach((b) => {
    b.classList.toggle("active", b.dataset.ring === currentRingFilter);
  });
}

function renderTimeline() {
  if (!analysisData) return;
  const container = document.getElementById("threatTimeline");
  const noThreats = document.getElementById("noThreats");
  const query = document.getElementById("searchBox").value.trim().toLowerCase();

  const timeline = analysisData.timeline || [];
  if (timeline.length === 0) {
    container.innerHTML = "";
    noThreats.classList.remove("hidden");
    return;
  }
  noThreats.classList.add("hidden");

  const filtered = timeline.filter((t) => {
    if (currentFilter !== "all" && t.severity !== currentFilter) return false;
    if (currentRingFilter === "ring0" && !t.category.toLowerCase().includes("ring 0")) return false;
    if (currentRingFilter === "ring3" && !t.category.toLowerCase().includes("ring 3")) return false;
    if (query) {
      const hay = `${t.process_name} ${t.operation} ${t.path} ${t.threat_type} ${t.category}`.toLowerCase();
      if (!hay.includes(query)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-state"><p>No threats match the selected filters.</p></div>';
    return;
  }

  container.innerHTML = "";
  filtered.forEach((t) => {
    const ringLabel = t.category.toLowerCase().includes("ring 0") ? "Ring 0 (Kernel)" :
                      t.category.toLowerCase().includes("ring 3") ? "Ring 3 (User)" : "Process";
    const card = document.createElement("div");
    card.className = `threat-card sev-${t.severity}`;
    card.onclick = () => showDetail(t);
    card.innerHTML = `
      <div style="min-width:0; flex:1;">
        <div class="threat-badges">
          <span class="mono" style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(t.timestamp)}</span>
          <span class="badge badge-${t.severity}">${SEV_EMOJI[t.severity] || ""} ${t.severity}</span>
          <span class="badge badge-ring">${ringLabel}</span>
          ${t.mitre_id && t.mitre_id !== "N/A" ? `<span class="badge badge-mitre mono">${escapeHtml(t.mitre_id)}</span>` : ""}
        </div>
        <div class="threat-title">${escapeHtml(t.threat_type)}</div>
        <div class="threat-proc">
          <strong>${escapeHtml(t.process_name)}</strong> (PID: ${escapeHtml(t.pid)}) → <span class="mono">${escapeHtml(t.operation)}</span>
        </div>
        ${t.path ? `<div class="threat-path mono">${escapeHtml(t.path)}</div>` : ""}
      </div>
      <span style="color:var(--text-muted); font-size:0.9rem;">▸</span>
    `;
    container.appendChild(card);
  });
}

// ── Threat Detail Modal ──────────────────────────────────────────────────
function showDetail(t) {
  const modal = document.getElementById("detailModal");
  const body = document.getElementById("detailContent");

  const related = (t.related_events || [])
    .map(
      (e) => `
      <div class="related-item mono">
        <span>${escapeHtml(e.timestamp)}</span>
        <strong style="color:var(--text-primary);">${escapeHtml(e.operation)}</strong>
        <span style="flex:1; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(e.path)}</span>
        <span>${escapeHtml(e.result)}</span>
      </div>`
    )
    .join("");

  body.innerHTML = `
    <div style="border-left:4px solid var(--sev-${t.severity}); padding-left:14px;">
      <span class="badge badge-${t.severity}">${SEV_EMOJI[t.severity] || ""} ${escapeHtml(t.severity)}</span>
      <h3 style="font-size:1.25rem; font-weight:700; margin-top:6px;">${escapeHtml(t.threat_type)}</h3>
      <p style="font-size:0.8rem; color:var(--text-secondary);">${escapeHtml(t.category)}</p>
    </div>

    <div class="detail-grid">
      <div><div class="detail-lbl">Timestamp</div><div class="detail-val mono">${escapeHtml(t.timestamp)}</div></div>
      <div><div class="detail-lbl">Process</div><div class="detail-val">${escapeHtml(t.process_name)} (PID: ${escapeHtml(t.pid)})</div></div>
      <div><div class="detail-lbl">Operation</div><div class="detail-val mono">${escapeHtml(t.operation)}</div></div>
      <div><div class="detail-lbl">Result</div><div class="detail-val">${escapeHtml(t.result || "N/A")}</div></div>
      ${t.mitre_id && t.mitre_id !== "N/A" ? `<div><div class="detail-lbl">MITRE ATT&CK</div><div class="detail-val mono" style="color:var(--accent-cyan);">${escapeHtml(t.mitre_id)}</div></div>` : ""}
    </div>

    ${t.path ? `<div style="margin-bottom:10px;"><div class="detail-lbl">Path / Target</div><div class="detail-val mono" style="font-size:0.82rem;">${escapeHtml(t.path)}</div></div>` : ""}
    ${t.detail ? `<div style="margin-bottom:10px;"><div class="detail-lbl">Detail</div><div class="detail-val mono" style="font-size:0.82rem;">${escapeHtml(t.detail)}</div></div>` : ""}

    <div class="why-box">
      <div class="detail-lbl" style="margin-bottom:6px;">Why This Is A Threat</div>
      <p style="font-size:0.88rem; color:#cbd5e1;">${escapeHtml(t.description)}</p>
    </div>

    ${related ? `<div style="margin-top:16px;"><div class="detail-lbl">Surrounding Events</div><div class="related-list">${related}</div></div>` : ""}
  `;

  modal.classList.remove("hidden");
}

function closeDetail() {
  document.getElementById("detailModal").classList.add("hidden");
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeDetail();
});

// ── Export & Reset ───────────────────────────────────────────────────────
function exportCSV() { window.location.href = "/api/export/csv"; }
function exportPDF() { window.location.href = "/api/export/pdf"; }

function newScan() {
  analysisData = null;
  clearFile();
  showScreen("upload");
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
