/**
 * Sentinel Security Analyzer Frontend Application.
 * Handles log uploads, live progress tracking, evidence inspection, and report export.
 */

let currentJobId = null;
let selectedFile = null;
let progressPollTimer = null;
let statusPollTimer = null;

// DOM Elements
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const fileDetailsBar = document.getElementById('fileDetailsBar');
const selectedFileName = document.getElementById('selectedFileName');
const selectedFileMeta = document.getElementById('selectedFileMeta');
const btnAnalyze = document.getElementById('btnAnalyze');

const modelStatusPill = document.getElementById('modelStatusPill');
const systemRamPill = document.getElementById('systemRamPill');

const progressSection = document.getElementById('progressSection');
const currentStageBadge = document.getElementById('currentStageBadge');
const elapsedTimer = document.getElementById('elapsedTimer');
const progressBarFill = document.getElementById('progressBarFill');
const chunkCounter = document.getElementById('chunkCounter');
const percentCounter = document.getElementById('percentCounter');
const tokenCounter = document.getElementById('tokenCounter');
const modelMemCounter = document.getElementById('modelMemCounter');
const liveActivityBox = document.getElementById('liveActivityBox');

const reportSection = document.getElementById('reportSection');
const reportIdTag = document.getElementById('reportIdTag');
const reportStatusTitle = document.getElementById('reportStatusTitle');
const executiveSummaryText = document.getElementById('executiveSummaryText');
const countTotal = document.getElementById('countTotal');
const countCritical = document.getElementById('countCritical');
const countHigh = document.getElementById('countHigh');
const countMedium = document.getElementById('countMedium');
const countLow = document.getElementById('countLow');
const entitiesTableBody = document.getElementById('entitiesTableBody');
const categoriesList = document.getElementById('categoriesList');
const findingsList = document.getElementById('findingsList');
const btnExportJson = document.getElementById('btnExportJson');

const contextModal = document.getElementById('contextModal');
const contextModalSubtitle = document.getElementById('contextModalSubtitle');
const logViewerLines = document.getElementById('logViewerLines');
const btnCloseModal = document.getElementById('btnCloseModal');

// Escape helper to prevent XSS from untrusted log strings
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// 1. Initial State & Status Polling
async function pollSystemStatus() {
  try {
    const res = await fetch('/api/model/status');
    if (res.ok) {
      const data = await res.json();
      const dot = modelStatusPill.querySelector('.status-dot');
      const label = modelStatusPill.querySelector('.status-label');

      if (data.ready) {
        dot.className = 'status-dot';
        label.textContent = `Model: Ready (${data.model_name})`;
      } else if (data.available) {
        dot.className = 'status-dot warning';
        label.textContent = 'Model: Starting runtime...';
      } else {
        dot.className = 'status-dot danger';
        label.textContent = 'Model: Missing weights';
      }

      const ramLabel = systemRamPill.querySelector('.status-label');
      ramLabel.textContent = `RAM: ${Math.round(data.model_memory_rss_mb)} MB (Model)`;
    }
  } catch (err) {
    console.warn('System status poll failed', err);
  }
}

// 2. Drag & Drop and File Selection
dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
    handleFileSelected(e.dataTransfer.files[0]);
  }
});

fileInput.addEventListener('change', (e) => {
  if (e.target.files && e.target.files.length > 0) {
    handleFileSelected(e.target.files[0]);
  }
});

function handleFileSelected(file) {
  const ext = file.name.slice((file.name.lastIndexOf(".") - 1 >>> 0) + 2).toLowerCase();
  if (ext !== 'log' && ext !== 'txt') {
    alert('Please select a valid .log or .txt file.');
    return;
  }

  selectedFile = file;
  selectedFileName.textContent = file.name;
  const sizeKb = (file.size / 1024).toFixed(1);
  selectedFileMeta.textContent = `${sizeKb} KB | Ready for upload`;

  fileDetailsBar.style.display = 'flex';
  btnAnalyze.disabled = false;
}

// 3. File Upload & Trigger Analysis
btnAnalyze.addEventListener('click', async () => {
  if (!selectedFile) return;

  btnAnalyze.disabled = true;
  btnAnalyze.textContent = 'Uploading...';

  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    const uploadRes = await fetch('/api/upload', {
      method: 'POST',
      body: formData
    });

    if (!uploadRes.ok) {
      const err = await uploadRes.json();
      throw new Error(err.detail || 'Upload failed');
    }

    const uploadData = await uploadRes.json();
    currentJobId = uploadData.job_id;

    // Trigger sequential analysis
    btnAnalyze.textContent = 'Enqueuing...';
    const analyzeRes = await fetch(`/api/analyze/${currentJobId}`, {
      method: 'POST'
    });

    if (!analyzeRes.ok) {
      const err = await analyzeRes.json();
      throw new Error(err.detail || 'Failed to trigger analysis');
    }

    // Switch UI to Live Progress
    progressSection.style.display = 'flex';
    reportSection.style.display = 'none';
    startProgressPolling(currentJobId);

  } catch (err) {
    alert(`Error: ${err.message}`);
    btnAnalyze.disabled = false;
    btnAnalyze.textContent = 'Start Security Analysis';
  }
});

// 4. Progress Polling
function startProgressPolling(jobId) {
  if (progressPollTimer) clearInterval(progressPollTimer);

  progressPollTimer = setInterval(async () => {
    try {
      const res = await fetch(`/api/jobs/${jobId}/progress`);
      if (!res.ok) return;

      const p = await res.json();

      currentStageBadge.textContent = p.current_stage;
      progressBarFill.style.width = `${p.percentage}%`;
      chunkCounter.textContent = `${p.current_chunk} / ${p.total_chunks}`;
      percentCounter.textContent = `${p.percentage}%`;
      tokenCounter.textContent = p.total_tokens.toLocaleString();
      modelMemCounter.textContent = `${Math.round(p.model_rss_mb)} MB`;

      const mins = Math.floor(p.elapsed_seconds / 60).toString().padStart(2, '0');
      const secs = Math.floor(p.elapsed_seconds % 60).toString().padStart(2, '0');
      elapsedTimer.textContent = `Elapsed: ${mins}:${secs}`;

      const activeText = `Processing Chunk ${p.current_chunk} of ${p.total_chunks} [Completed: ${p.completed_chunks}, Failed: ${p.failed_chunks}] - Stage: ${p.current_stage}`;
      liveActivityBox.innerHTML = `<div class="live-activity-line">&gt; ${escapeHtml(activeText)}</div>`;

      if (p.status === 'COMPLETED') {
        clearInterval(progressPollTimer);
        progressPollTimer = null;
        liveActivityBox.innerHTML += `<div class="live-activity-line" style="color: #38bdf8;">[+] Analysis complete! Loading consolidated incident report...</div>`;
        setTimeout(() => loadReport(jobId), 800);
      } else if (p.status === 'FAILED') {
        clearInterval(progressPollTimer);
        progressPollTimer = null;
        alert('Analysis encountered an error. Please inspect logs.');
        btnAnalyze.disabled = false;
        btnAnalyze.textContent = 'Start Security Analysis';
      }
    } catch (err) {
      console.warn('Progress poll error', err);
    }
  }, 1000);
}

// 5. Load & Render Report
async function loadReport(jobId) {
  try {
    const res = await fetch(`/api/reports/${jobId}`);
    if (!res.ok) throw new Error('Report could not be retrieved.');

    const report = await res.json();
    renderReport(report);
  } catch (err) {
    alert(`Failed to load report: ${err.message}`);
  }
}

function renderReport(report) {
  reportSection.style.display = 'flex';

  reportIdTag.textContent = `REPORT: ${report.report_id} | ${report.filename}`;
  reportStatusTitle.textContent = report.overall_status;
  executiveSummaryText.textContent = report.executive_summary;

  // Stats
  countTotal.textContent = report.statistics.total;
  countCritical.textContent = report.statistics.critical;
  countHigh.textContent = report.statistics.high;
  countMedium.textContent = report.statistics.medium;
  countLow.textContent = report.statistics.low;

  // Entities Table
  entitiesTableBody.innerHTML = '';
  (report.suspicious_entities || []).forEach(ent => {
    const tr = document.createElement('tr');
    const badgeClass = `badge badge-${(ent.max_severity || 'low').toLowerCase()}`;
    const linesStr = (ent.evidence_lines || []).slice(0, 5).join(', ') + ((ent.evidence_lines || []).length > 5 ? '...' : '');

    tr.innerHTML = `
      <td><strong>${escapeHtml(ent.ip)}</strong></td>
      <td>${escapeHtml(ent.target_account || 'N/A')}</td>
      <td><span class="${badgeClass}">${escapeHtml(ent.max_severity)}</span></td>
      <td>${ent.incidents}</td>
      <td>Lines: ${escapeHtml(linesStr)}</td>
    `;
    entitiesTableBody.appendChild(tr);
  });

  // Category Distribution
  categoriesList.innerHTML = '';
  for (const [catName, catCount] of Object.entries(report.attack_category_distribution || {})) {
    const item = document.createElement('div');
    item.className = 'cat-item';
    item.innerHTML = `
      <span class="cat-name">${escapeHtml(catName)}</span>
      <span class="cat-count">${catCount}</span>
    `;
    categoriesList.appendChild(item);
  }

  // Findings List
  findingsList.innerHTML = '';
  (report.findings || []).forEach((f, idx) => {
    const fItem = document.createElement('div');
    fItem.className = 'finding-item';

    const sev = (f.severity || 'low').toLowerCase();
    const badgeClass = `badge badge-${sev}`;

    let evidenceRows = '';
    (f.evidence || []).forEach(ev => {
      evidenceRows += `
        <tr>
          <td class="evidence-line-num">Line ${ev.line}</td>
          <td>${escapeHtml(ev.excerpt)}</td>
          <td style="text-align: right;">
            <button class="btn-inspect-line" onclick="inspectEvidenceLine(${ev.line})">View Context</button>
          </td>
        </tr>
      `;
    });

    fItem.innerHTML = `
      <div class="finding-header" onclick="toggleFinding(${idx})">
        <div class="finding-title-group">
          <span class="${badgeClass}">${escapeHtml(f.severity)}</span>
          <span class="finding-title">${escapeHtml(f.attack_type)}</span>
          <span class="finding-entity">${escapeHtml(f.source_ip)}${f.account ? ' (' + escapeHtml(f.account) + ')' : ''}</span>
        </div>
        <span class="badge" style="background:#1c212c; color:#8b949e;">${escapeHtml(f.disposition || 'Suspicious')}</span>
      </div>

      <div class="finding-body" id="findingBody_${idx}">
        <div>
          <div class="finding-section-title">Analysis & Reason</div>
          <div class="finding-text">${escapeHtml(f.reason)}</div>
        </div>

        <div>
          <div class="finding-section-title">Evidence & Original Citations</div>
          <table class="evidence-table">
            <tbody>${evidenceRows}</tbody>
          </table>
        </div>

        <div>
          <div class="finding-section-title">Actionable Recommendation</div>
          <div class="finding-text" style="color: #7ee787;">${escapeHtml(f.suggested_action)}</div>
        </div>

        <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">
          Confidence Score: ${(f.confidence * 100).toFixed(0)}% | Scope: Lines ${f.first_line || 'N/A'} - ${f.last_line || 'N/A'}
        </div>
      </div>
    `;

    findingsList.appendChild(fItem);
  });

  // Export Button Handler
  btnExportJson.onclick = () => {
    window.location.href = `/api/reports/${report.job_id}/export`;
  };
}

// Toggle Finding Accordion
window.toggleFinding = function(idx) {
  const body = document.getElementById(`findingBody_${idx}`);
  if (body) {
    body.style.display = body.style.display === 'none' ? 'flex' : 'none';
  }
};

// 6. Evidence Log Context Inspection Modal
window.inspectEvidenceLine = async function(line) {
  if (!currentJobId) return;

  contextModalSubtitle.textContent = `Displaying authentic context lines surrounding Line ${line}`;
  logViewerLines.innerHTML = '<div>Loading log context...</div>';
  contextModal.style.display = 'flex';

  try {
    const res = await fetch(`/api/logs/${currentJobId}/context?line=${line}&window=5`);
    if (!res.ok) throw new Error('Could not retrieve context.');

    const data = await res.json();
    logViewerLines.innerHTML = '';

    (data.lines || []).forEach(row => {
      const lineDiv = document.createElement('div');
      lineDiv.className = `log-row ${row.is_target ? 'target-line' : ''}`;
      lineDiv.innerHTML = `
        <span class="log-num">${row.line}</span>
        <span class="log-content">${escapeHtml(row.text)}</span>
      `;
      logViewerLines.appendChild(lineDiv);
    });
  } catch (err) {
    logViewerLines.innerHTML = `<div style="color: #f85149;">Error loading context: ${escapeHtml(err.message)}</div>`;
  }
};

btnCloseModal.addEventListener('click', () => {
  contextModal.style.display = 'none';
});

contextModal.addEventListener('click', (e) => {
  if (e.target === contextModal) {
    contextModal.style.display = 'none';
  }
});

// Start Status Polling Loop
pollSystemStatus();
statusPollTimer = setInterval(pollSystemStatus, 3000);
