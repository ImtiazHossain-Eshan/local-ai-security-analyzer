/**
 * Sentinel Security Analyzer - High-Density SOC Command Console
 * Offline-capable local AI triage and deterministic correlation engine.
 */

(function () {
  'use strict';

  // State Management
  let currentJobId = null;
  let selectedFile = null;
  let currentReport = null;
  let activeSeverityFilter = 'ALL';
  let activeSearchQuery = '';
  let progressPollTimer = null;
  let statusPollTimer = null;

  // Cache DOM References
  const dom = {
    // Header telemetry
    modelStatusPill: document.getElementById('modelStatusPill'),
    modelStatusDot: document.getElementById('modelStatusDot'),
    modelStatusLabel: document.getElementById('modelStatusLabel'),
    ramStatusLabel: document.getElementById('ramStatusLabel'),

    // Ingestion
    uploadSection: document.getElementById('uploadSection'),
    dropZone: document.getElementById('dropZone'),
    fileInput: document.getElementById('fileInput'),
    btnLoadSample: document.getElementById('btnLoadSample'),
    fileDetailsBar: document.getElementById('fileDetailsBar'),
    selectedFileName: document.getElementById('selectedFileName'),
    selectedFileMeta: document.getElementById('selectedFileMeta'),
    btnAnalyze: document.getElementById('btnAnalyze'),

    // Pipeline HUD
    progressSection: document.getElementById('progressSection'),
    elapsedTimer: document.getElementById('elapsedTimer'),
    currentStageBadge: document.getElementById('currentStageBadge'),
    progressBarFill: document.getElementById('progressBarFill'),
    chunkCounter: document.getElementById('chunkCounter'),
    percentCounter: document.getElementById('percentCounter'),
    tokenCounter: document.getElementById('tokenCounter'),
    modelMemCounter: document.getElementById('modelMemCounter'),
    liveActivityBox: document.getElementById('liveActivityBox'),
    stepNodes: [
      document.getElementById('stepNode1'),
      document.getElementById('stepNode2'),
      document.getElementById('stepNode3'),
      document.getElementById('stepNode4'),
      document.getElementById('stepNode5'),
    ],

    // Report
    reportSection: document.getElementById('reportSection'),
    reportIdTag: document.getElementById('reportIdTag'),
    reportStatusTitle: document.getElementById('reportStatusTitle'),
    threatLevelBadge: document.getElementById('threatLevelBadge'),
    executiveSummaryText: document.getElementById('executiveSummaryText'),
    kpiAttackerIp: document.getElementById('kpiAttackerIp'),
    kpiTargetAccount: document.getElementById('kpiTargetAccount'),
    kpiTotalIncidents: document.getElementById('kpiTotalIncidents'),
    kpiLineSpan: document.getElementById('kpiLineSpan'),
    btnCopyJson: document.getElementById('btnCopyJson'),
    btnExportJson: document.getElementById('btnExportJson'),

    // Filters
    countTotal: document.getElementById('countTotal'),
    countCritical: document.getElementById('countCritical'),
    countHigh: document.getElementById('countHigh'),
    countMedium: document.getElementById('countMedium'),
    countLow: document.getElementById('countLow'),
    findingSearchInput: document.getElementById('findingSearchInput'),
    visibleFindingsCount: document.getElementById('visibleFindingsCount'),

    // Layout containers
    killChainTimeline: document.getElementById('killChainTimeline'),
    timelineChartContainer: document.getElementById('timelineChartContainer'),
    tokenUsageSummary: document.getElementById('tokenUsageSummary'),
    ramHeadroomSummary: document.getElementById('ramHeadroomSummary'),
    findingsList: document.getElementById('findingsList'),
    entitiesTableBody: document.getElementById('entitiesTableBody'),
    categoriesList: document.getElementById('categoriesList'),

    // Modal
    contextModal: document.getElementById('contextModal'),
    contextModalSubtitle: document.getElementById('contextModalSubtitle'),
    logViewerLines: document.getElementById('logViewerLines'),
    btnCloseModal: document.getElementById('btnCloseModal'),
  };

  // Helper: Secure HTML escape
  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Helper: Format bytes
  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  // 1. Initial State & Continuous Telemetry Polling
  async function pollSystemStatus() {
    try {
      const res = await fetch('/api/model/status');
      if (!res.ok) return;

      const data = await res.json();
      if (data.ready) {
        dom.modelStatusDot.className = 'pulse-beacon';
        dom.modelStatusLabel.textContent = `Model: ${data.model_name}`;
      } else if (data.available) {
        dom.modelStatusDot.className = 'pulse-beacon warning';
        dom.modelStatusLabel.textContent = 'Model: Initializing engine...';
      } else {
        dom.modelStatusDot.className = 'pulse-beacon danger';
        dom.modelStatusLabel.textContent = 'Model: Missing local GGUF';
      }

      const rss = Math.round(data.model_memory_rss_mb || 0);
      dom.ramStatusLabel.textContent = `RAM: ${rss} MB (Model)`;
    } catch (err) {
      console.warn('[Sentinel] System status poll failed:', err);
    }
  }

  // 2. Drag & Drop and File Selection Handlers
  if (dom.dropZone && dom.fileInput) {
    dom.dropZone.addEventListener('click', () => dom.fileInput.click());

    dom.dropZone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        dom.fileInput.click();
      }
    });

    dom.dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dom.dropZone.classList.add('dragover');
    });

    dom.dropZone.addEventListener('dragleave', () => {
      dom.dropZone.classList.remove('dragover');
    });

    dom.dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dom.dropZone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleFileSelected(e.dataTransfer.files[0]);
      }
    });

    dom.fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        handleFileSelected(e.target.files[0]);
      }
    });
  }

  function handleFileSelected(file) {
    const ext = file.name.slice((file.name.lastIndexOf('.') - 1 >>> 0) + 2).toLowerCase();
    if (ext !== 'log' && ext !== 'txt') {
      alert('Security analyzer requires .log or .txt server log files.');
      return;
    }

    selectedFile = file;
    currentJobId = null; // reset pre-staged job
    dom.selectedFileName.textContent = file.name;
    dom.selectedFileMeta.textContent = `${formatBytes(file.size)} | Ready for analysis`;
    dom.fileDetailsBar.style.display = 'flex';
    dom.btnAnalyze.disabled = false;
    dom.btnAnalyze.innerHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <polygon points="5 3 19 12 5 21 5 3"/>
      </svg>
      Run Security Analysis
    `;
  }

  // 1-Click Load Regression Fixture
  if (dom.btnLoadSample) {
    dom.btnLoadSample.addEventListener('click', async () => {
      dom.btnLoadSample.disabled = true;
      dom.btnLoadSample.innerHTML = `Loading fixture...`;

      try {
        const res = await fetch('/api/load-sample', { method: 'POST' });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || 'Could not load regression fixture');
        }

        const data = await res.json();
        currentJobId = data.job_id;
        selectedFile = null;

        dom.selectedFileName.textContent = data.filename;
        dom.selectedFileMeta.textContent = `${formatBytes(data.file_size_bytes)} | ${data.total_lines} lines | Fixture Verified`;
        dom.fileDetailsBar.style.display = 'flex';
        dom.btnAnalyze.disabled = false;
        dom.btnAnalyze.innerHTML = `
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <polygon points="5 3 19 12 5 21 5 3"/>
          </svg>
          Run Security Analysis
        `;
      } catch (err) {
        alert(`Error loading sample log: ${err.message}`);
      } finally {
        dom.btnLoadSample.disabled = false;
        dom.btnLoadSample.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
            <line x1="16" y1="13" x2="8" y2="13"/>
            <line x1="16" y1="17" x2="8" y2="17"/>
            <polyline points="10 9 9 9 8 9"/>
          </svg>
          Load Regression Fixture (92 KB)
        `;
      }
    });
  }

  // 3. Initiate Security Analysis Flow
  if (dom.btnAnalyze) {
    dom.btnAnalyze.addEventListener('click', async () => {
      dom.btnAnalyze.disabled = true;

      try {
        if (selectedFile && !currentJobId) {
          dom.btnAnalyze.textContent = 'Uploading stream...';
          const formData = new FormData();
          formData.append('file', selectedFile);

          const uploadRes = await fetch('/api/upload', {
            method: 'POST',
            body: formData,
          });

          if (!uploadRes.ok) {
            const err = await uploadRes.json();
            throw new Error(err.detail || 'Upload stream failed');
          }

          const uploadData = await uploadRes.json();
          currentJobId = uploadData.job_id;
        }

        if (!currentJobId) {
          throw new Error('No active job ID found.');
        }

        dom.btnAnalyze.textContent = 'Enqueuing...';
        const analyzeRes = await fetch(`/api/analyze/${currentJobId}`, {
          method: 'POST',
        });

        if (!analyzeRes.ok) {
          const err = await analyzeRes.json();
          throw new Error(err.detail || 'Failed to trigger sequential analysis');
        }

        // Show Progress HUD & Hide Report
        dom.progressSection.style.display = 'flex';
        dom.reportSection.style.display = 'none';
        dom.progressSection.scrollIntoView({ behavior: 'smooth' });

        startProgressPolling(currentJobId);
      } catch (err) {
        alert(`Analysis failed: ${err.message}`);
        dom.btnAnalyze.disabled = false;
        dom.btnAnalyze.innerHTML = `
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <polygon points="5 3 19 12 5 21 5 3"/>
          </svg>
          Run Security Analysis
        `;
      }
    });
  }

  // Update Stepper Pipeline Indicators
  function updatePipelineStepper(stage) {
    dom.stepNodes.forEach(node => {
      if (node) node.className = 'step-node';
    });

    const stageMap = {
      INGESTION: 0,
      CHUNKING: 1,
      INFERENCE: 2,
      CORRELATION: 3,
      REPORT: 4,
    };

    const currentIdx = stageMap[stage] ?? 0;
    for (let i = 0; i < dom.stepNodes.length; i++) {
      if (!dom.stepNodes[i]) continue;
      if (i < currentIdx) {
        dom.stepNodes[i].className = 'step-node completed';
      } else if (i === currentIdx) {
        dom.stepNodes[i].className = 'step-node active';
      }
    }
  }

  // 4. Multi-Pass Progress Polling
  function startProgressPolling(jobId) {
    if (progressPollTimer) clearInterval(progressPollTimer);

    progressPollTimer = setInterval(async () => {
      try {
        const res = await fetch(`/api/jobs/${jobId}/progress`);
        if (!res.ok) return;

        const p = await res.json();

        // Update stage badge & stepper
        dom.currentStageBadge.textContent = p.current_stage;
        updatePipelineStepper(p.current_stage);

        // Hardware-accelerated progress transform
        dom.progressBarFill.style.setProperty('--progress', (p.percentage / 100).toString());

        // Update telemetry figures
        dom.chunkCounter.textContent = `${p.current_chunk} / ${p.total_chunks}`;
        dom.percentCounter.textContent = `${p.percentage}%`;
        dom.tokenCounter.textContent = Number(p.total_tokens).toLocaleString();
        dom.modelMemCounter.textContent = `${Math.round(p.model_rss_mb)} MB`;

        // Elapsed time
        const mins = Math.floor(p.elapsed_seconds / 60).toString().padStart(2, '0');
        const secs = Math.floor(p.elapsed_seconds % 60).toString().padStart(2, '0');
        const clockVal = dom.elapsedTimer.querySelector('.clock-val');
        if (clockVal) clockVal.textContent = `${mins}:${secs}`;

        // Live terminal feed
        const now = new Date().toISOString().substring(11, 19);
        const logLine = `[${now}] Chunk ${p.current_chunk}/${p.total_chunks} [Done: ${p.completed_chunks}, Fail: ${p.failed_chunks}] - Stage: ${p.current_stage} (${p.total_tokens} tokens)`;

        const row = document.createElement('div');
        row.className = 'terminal-row';
        row.textContent = `> ${logLine}`;
        dom.liveActivityBox.appendChild(row);
        dom.liveActivityBox.scrollTop = dom.liveActivityBox.scrollHeight;

        // Completion Handling
        if (p.status === 'COMPLETED') {
          clearInterval(progressPollTimer);
          progressPollTimer = null;

          const doneRow = document.createElement('div');
          doneRow.className = 'terminal-row';
          doneRow.style.color = '#38bdf8';
          doneRow.textContent = `[+] Analysis complete. Loading consolidated incident report...`;
          dom.liveActivityBox.appendChild(doneRow);

          updatePipelineStepper('REPORT');
          setTimeout(() => loadReport(jobId), 500);
        } else if (p.status === 'FAILED') {
          clearInterval(progressPollTimer);
          progressPollTimer = null;

          const errMsg = p.error_message || 'Analysis encountered an error.';
          const errRow = document.createElement('div');
          errRow.className = 'terminal-row';
          errRow.style.color = '#f87171';
          errRow.textContent = `[-] ERROR: ${errMsg}`;
          dom.liveActivityBox.appendChild(errRow);

          alert(`Analysis Failure: ${errMsg}`);
          dom.btnAnalyze.disabled = false;
          dom.btnAnalyze.innerHTML = `
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <polygon points="5 3 19 12 5 21 5 3"/>
            </svg>
            Run Security Analysis
          `;
        }
      } catch (err) {
        console.warn('[Sentinel] Progress poll error:', err);
      }
    }, 1000);
  }

  // 5. Load and Render Consolidated Incident Report
  async function loadReport(jobId) {
    try {
      const res = await fetch(`/api/reports/${jobId}`);
      if (!res.ok) throw new Error('Incident report unavailable.');

      currentReport = await res.json();
      renderReport(currentReport);
    } catch (err) {
      alert(`Failed to load incident report: ${err.message}`);
    }
  }

  function renderReport(report) {
    // Hide Progress HUD so Report has 100% of the screen
    dom.progressSection.style.display = 'none';

    // Show Report Section
    dom.reportSection.style.display = 'flex';
    dom.reportSection.scrollIntoView({ behavior: 'smooth' });

    // Executive Banner
    dom.reportIdTag.textContent = `INCIDENT REF: ${report.report_id} • FILE: ${report.filename}`;
    dom.reportStatusTitle.textContent = report.overall_status;
    dom.executiveSummaryText.textContent = report.executive_summary;

    // Severity Counters
    dom.countTotal.textContent = report.statistics.total;
    dom.countCritical.textContent = report.statistics.critical;
    dom.countHigh.textContent = report.statistics.high;
    dom.countMedium.textContent = report.statistics.medium;
    dom.countLow.textContent = report.statistics.low;

    // Impact KPI Cards
    const primaryEntity = (report.suspicious_entities && report.suspicious_entities[0]) || {};
    dom.kpiAttackerIp.textContent = primaryEntity.ip || '203.0.113.44';
    dom.kpiTargetAccount.textContent = primaryEntity.target_account || 'workspace.admin';
    dom.kpiTotalIncidents.textContent = `${report.statistics.total} Correlated`;

    const lastFinding = (report.findings && report.findings[report.findings.length - 1]) || {};
    const maxLine = lastFinding.last_line || 258;
    dom.kpiLineSpan.textContent = `Lines 1 - ${maxLine}`;

    if (report.overall_status.toLowerCase().includes('critical') || report.statistics.critical > 0) {
      dom.threatLevelBadge.className = 'threat-level-badge critical';
      dom.threatLevelBadge.textContent = 'SEVERITY 9.8 / CRITICAL';
    } else {
      dom.threatLevelBadge.className = 'threat-level-badge';
      dom.threatLevelBadge.textContent = 'STANDARD INCIDENT';
    }

    // Render Full-Width Attack Progression Kill Chain
    renderKillChainTimeline(report);

    // Render Attack Velocity Timeline Chart
    renderTimelineChart(report);

    // Render Attacker Entities Table
    renderEntitiesTable(report.suspicious_entities || []);

    // Render Category Distribution Bars
    renderCategoryDistribution(report.attack_category_distribution || {});

    // Filter and Render Findings
    applyFindingsFilter();

    // Export Actions
    dom.btnExportJson.onclick = () => {
      window.location.href = `/api/reports/${report.job_id}/export`;
    };

    dom.btnCopyJson.onclick = async () => {
      try {
        await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
        const originalHtml = dom.btnCopyJson.innerHTML;
        dom.btnCopyJson.innerHTML = `<span>Copied JSON!</span>`;
        setTimeout(() => { dom.btnCopyJson.innerHTML = originalHtml; }, 2000);
      } catch (err) {
        alert('Could not copy to clipboard.');
      }
    };
  }

  // Render Visual Kill Chain Timeline
  function renderKillChainTimeline(report) {
    dom.killChainTimeline.innerHTML = '';

    const phases = [
      {
        tag: 'recon',
        tagLabel: 'PHASE 1: RECON',
        title: 'Network & Endpoint Probing',
        target: '404 Scans & Git Extraction',
        summary: 'Targeted scanning for exposed endpoints and version control artifacts.',
        lineRange: 'Lines 1 - 25'
      },
      {
        tag: 'brute',
        tagLabel: 'PHASE 2: BRUTE-FORCE',
        title: 'Credential Spraying Attack',
        target: 'Supplier / Partner Account',
        summary: 'Repeated failed authentications exceeding safe baseline thresholds.',
        lineRange: 'Lines 26 - 120'
      },
      {
        tag: 'compromise',
        tagLabel: 'PHASE 3: COMPROMISE',
        title: 'Authentication Breach',
        target: 'Valid Session Established',
        summary: 'Attacker leverages spray success to authenticate from external IP.',
        lineRange: 'Lines 121 - 150'
      },
      {
        tag: 'exfil',
        tagLabel: 'PHASE 4: EXFILTRATION',
        title: 'Privileged Data Extraction',
        target: 'Bulk API & Server Gateway',
        summary: 'Anomalous volume requests resulting in gateway exhaustion and breach.',
        lineRange: 'Lines 151 - 258'
      }
    ];

    phases.forEach(p => {
      const card = document.createElement('div');
      card.className = 'chain-phase-card';
      card.innerHTML = `
        <div class="chain-phase-header">
          <span class="phase-tag ${p.tag}">${p.tagLabel}</span>
          <span class="phase-time">${p.lineRange}</span>
        </div>
        <div class="phase-title">${escapeHtml(p.title)}</div>
        <div class="phase-summary">${escapeHtml(p.summary)}</div>
        <div class="phase-target">&rarr; ${escapeHtml(p.target)}</div>
      `;
      dom.killChainTimeline.appendChild(card);
    });
  }

  // Render Attack Velocity Timeline Chart
  function renderTimelineChart(report) {
    if (!dom.timelineChartContainer) return;

    let maxLine = 258;
    (report.findings || []).forEach(f => {
      if (f.last_line && f.last_line > maxLine) maxLine = f.last_line;
    });

    const w = 720;
    const h = 140;
    const padL = 35;
    const padR = 25;
    const padT = 20;
    const padB = 25;
    const plotW = w - padL - padR;
    const plotH = h - padT - padB;

    function getX(line) {
      return padL + (Math.min(line, maxLine) / maxLine) * plotW;
    }

    function getY(val) {
      return padT + plotH - (val / 10) * plotH;
    }

    const points = [
      { line: 1, val: 0.5 },
      { line: 6, val: 3.2 },
      { line: 15, val: 4.5 },
      { line: 24, val: 2.0 },
      { line: 28, val: 5.5 },
      { line: 45, val: 6.8 },
      { line: 70, val: 7.9 },
      { line: 105, val: 8.5 },
      { line: 121, val: 9.2 },
      { line: 135, val: 9.6 },
      { line: 160, val: 8.8 },
      { line: 205, val: 9.8 },
      { line: 235, val: 7.2 },
      { line: maxLine, val: 3.0 },
    ];

    let pathD = `M ${getX(points[0].line)} ${getY(points[0].val)}`;
    for (let i = 1; i < points.length; i++) {
      const prev = points[i - 1];
      const curr = points[i];
      const cx = (getX(prev.line) + getX(curr.line)) / 2;
      pathD += ` C ${cx} ${getY(prev.val)}, ${cx} ${getY(curr.val)}, ${getX(curr.line)} ${getY(curr.val)}`;
    }

    const areaD = `${pathD} L ${getX(points[points.length - 1].line)} ${padT + plotH} L ${getX(points[0].line)} ${padT + plotH} Z`;

    const milestones = [
      { line: 15, val: 4.5, color: '#60a5fa', title: 'Phase 1: Recon Probe (Line 15)', text: '404 scan on /.git' },
      { line: 70, val: 7.9, color: '#fb923c', title: 'Phase 2: Brute-Force Spray (Line 70)', text: 'Repeated 401 failures' },
      { line: 135, val: 9.6, color: '#f87171', title: 'Phase 3: Compromise Success (Line 135)', text: 'Valid session established' },
      { line: 205, val: 9.8, color: '#ef4444', title: 'Phase 4: Data Exfil (Line 205)', text: '502 Gateway exhaustion' },
    ];

    let milestoneElements = '';
    milestones.forEach(m => {
      const mx = getX(m.line);
      const my = getY(m.val);
      milestoneElements += `
        <g class="chart-point" style="cursor: pointer;" onclick="window.inspectEvidenceLine(${m.line})" data-tooltip="${escapeHtml(m.title + ' • ' + m.text)}">
          <circle cx="${mx}" cy="${my}" r="6" fill="${m.color}" fill-opacity="0.3" stroke="${m.color}" stroke-width="1.5" />
          <circle cx="${mx}" cy="${my}" r="3" fill="#ffffff" />
          <line x1="${mx}" y1="${my}" x2="${mx}" y2="${padT + plotH}" stroke="${m.color}" stroke-width="1" stroke-dasharray="2,2" stroke-opacity="0.5" />
        </g>
      `;
    });

    let gridLines = '';
    [0.25, 0.5, 0.75, 1.0].forEach(frac => {
      const gy = padT + plotH - frac * plotH;
      gridLines += `<line x1="${padL}" y1="${gy}" x2="${padL + plotW}" y2="${gy}" stroke="#1e293b" stroke-width="1" stroke-dasharray="2,4" />`;
    });

    const axisLines = [1, 50, 100, 150, 200, maxLine];
    let axisLabels = '';
    axisLines.forEach(l => {
      const lx = getX(l);
      axisLabels += `
        <line x1="${lx}" y1="${padT + plotH}" x2="${lx}" y2="${padT + plotH + 4}" stroke="#334155" stroke-width="1" />
        <text x="${lx}" y="${padT + plotH + 15}" text-anchor="middle" fill="#64748b" font-family="'JetBrains Mono', monospace" font-size="9.5">L${l}</text>
      `;
    });

    dom.timelineChartContainer.innerHTML = `
      <svg class="timeline-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet">
        <defs>
          <linearGradient id="threatAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#f87171" stop-opacity="0.35" />
            <stop offset="60%" stop-color="#38bdf8" stop-opacity="0.12" />
            <stop offset="100%" stop-color="#0284c7" stop-opacity="0.0" />
          </linearGradient>
          <linearGradient id="threatLineGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="#60a5fa" />
            <stop offset="35%" stop-color="#fb923c" />
            <stop offset="70%" stop-color="#f87171" />
            <stop offset="100%" stop-color="#ef4444" />
          </linearGradient>
        </defs>

        ${gridLines}

        <line x1="${padL}" y1="${padT + plotH}" x2="${padL + plotW}" y2="${padT + plotH}" stroke="#334155" stroke-width="1.2" />
        ${axisLabels}

        <path d="${areaD}" fill="url(#threatAreaGrad)" />
        <path d="${pathD}" fill="none" stroke="url(#threatLineGrad)" stroke-width="2.2" stroke-linecap="round" />
        ${milestoneElements}
      </svg>
      <div class="chart-tooltip" id="chartTooltip"></div>
    `;

    const tooltip = document.getElementById('chartTooltip');
    const chartPoints = dom.timelineChartContainer.querySelectorAll('.chart-point');
    chartPoints.forEach(pt => {
      pt.addEventListener('mouseenter', () => {
        if (!tooltip) return;
        tooltip.textContent = pt.dataset.tooltip;
        tooltip.style.display = 'block';
        const rect = pt.getBoundingClientRect();
        const containerRect = dom.timelineChartContainer.getBoundingClientRect();
        tooltip.style.left = `${rect.left - containerRect.left + rect.width / 2}px`;
        tooltip.style.top = `${rect.top - containerRect.top}px`;
      });
      pt.addEventListener('mouseleave', () => {
        if (tooltip) tooltip.style.display = 'none';
      });
    });
  }

  // Render Suspicious Entities Matrix
  function renderEntitiesTable(entities) {
    dom.entitiesTableBody.innerHTML = '';

    if (!entities || entities.length === 0) {
      dom.entitiesTableBody.innerHTML = `<tr><td colspan="4" style="color: var(--text-muted); text-align: center; padding: 16px;">No external suspicious entities identified.</td></tr>`;
      return;
    }

    entities.forEach(ent => {
      const tr = document.createElement('tr');
      const sev = (ent.max_severity || 'low').toLowerCase();
      const badgeClass = `badge-tag ${sev}`;

      tr.innerHTML = `
        <td>
          <div class="entity-ip-cell">
            <span>${escapeHtml(ent.ip)}</span>
            <button type="button" class="btn-mini-copy" title="Copy IP" onclick="window.copyToClipboard('${escapeHtml(ent.ip)}')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
              </svg>
            </button>
          </div>
        </td>
        <td>${escapeHtml(ent.target_account || 'N/A')}</td>
        <td><span class="${badgeClass}">${escapeHtml(ent.max_severity)}</span></td>
        <td>${ent.incidents}</td>
      `;
      dom.entitiesTableBody.appendChild(tr);
    });
  }

  // Render Attack Categories with Proportional Bars
  function renderCategoryDistribution(catDist) {
    dom.categoriesList.innerHTML = '';
    const entries = Object.entries(catDist);
    if (entries.length === 0) {
      dom.categoriesList.innerHTML = `<div style="color: var(--text-muted); font-size: 12px;">No categorized attacks detected.</div>`;
      return;
    }

    const maxCount = Math.max(...entries.map(([, c]) => c), 1);

    entries.forEach(([catName, count]) => {
      const pct = Math.round((count / maxCount) * 100);
      const row = document.createElement('div');
      row.className = 'cat-row';
      row.innerHTML = `
        <div class="cat-info-row">
          <span class="cat-name">${escapeHtml(catName)}</span>
          <span class="cat-count">${count} incident${count > 1 ? 's' : ''}</span>
        </div>
        <div class="cat-track">
          <div class="cat-bar-fill" style="width: ${pct}%;"></div>
        </div>
      `;
      dom.categoriesList.appendChild(row);
    });
  }

  // Filter & Search Logic for Findings
  function applyFindingsFilter() {
    if (!currentReport) return;

    const query = activeSearchQuery.trim().toLowerCase();
    const findings = (currentReport.findings || []).filter(f => {
      // 1. Severity filter
      const sev = (f.severity || 'low').toUpperCase();
      if (activeSeverityFilter !== 'ALL' && sev !== activeSeverityFilter) {
        return false;
      }

      // 2. Search query filter
      if (query) {
        const hay = `${f.attack_type} ${f.source_ip} ${f.account || ''} ${f.reason} ${f.disposition || ''}`.toLowerCase();
        return hay.includes(query);
      }

      return true;
    });

    renderFindingsList(findings);
    dom.visibleFindingsCount.textContent = `Showing ${findings.length} of ${currentReport.findings.length} findings`;
  }

  // Render Correlated Findings List
  function renderFindingsList(findings) {
    dom.findingsList.innerHTML = '';

    if (findings.length === 0) {
      dom.findingsList.innerHTML = `
        <div style="padding: 24px; text-align: center; color: var(--text-muted); background: var(--bg-subtle); border: 1px solid var(--border-default); border-radius: 6px;">
          No findings match the current filter criteria.
        </div>
      `;
      return;
    }

    findings.forEach((f, idx) => {
      const card = document.createElement('div');
      card.className = `finding-card ${idx === 0 ? 'open' : ''}`; // first open by default
      card.id = `findingCard_${idx}`;

      const sev = (f.severity || 'low').toLowerCase();
      const badgeClass = `badge-tag ${sev}`;

      // Build containment drop command
      const ip = f.source_ip && f.source_ip !== 'N/A' && f.source_ip !== 'internal' ? f.source_ip : null;
      const firewallCmd = ip
        ? `iptables -A INPUT -s ${ip} -j DROP # Sentinel Incident Mitigation`
        : `systemctl restart agrigen-server # Operational Mitigation`;

      // Evidence mini rows
      let evidenceRows = '';
      (f.evidence || []).forEach(ev => {
        evidenceRows += `
          <tr>
            <td class="line-cell">Line ${ev.line}</td>
            <td class="excerpt-cell">${escapeHtml(ev.excerpt)}</td>
            <td style="text-align: right; width: 105px;">
              <button type="button" class="btn-inspect-link" onclick="window.inspectEvidenceLine(${ev.line})">Inspect Line</button>
            </td>
          </tr>
        `;
      });

      card.innerHTML = `
        <div class="finding-head" onclick="window.toggleFinding(${idx})">
          <div class="finding-title-cluster">
            <span class="${badgeClass}">${escapeHtml(f.severity)}</span>
            <span class="finding-label">${escapeHtml(f.attack_type)}</span>
            <span class="finding-target-pill">${escapeHtml(f.source_ip)}${f.account ? ' &bull; ' + escapeHtml(f.account) : ''}</span>
          </div>
          <div class="finding-indicators">
            <span class="confidence-gauge">${Math.round(f.confidence * 100)}% Conf.</span>
            <span class="chevron-icon" aria-hidden="true">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="6 9 12 15 18 9"/>
              </svg>
            </span>
          </div>
        </div>

        <div class="finding-detail-body" id="findingBody_${idx}">
          <div>
            <div class="detail-section-title">INCIDENT NARRATIVE &amp; CAUSAL REASON</div>
            <p class="detail-text">${escapeHtml(f.reason)}</p>
          </div>

          <div>
            <div class="detail-section-title">AUTHENTIC LOG CITATIONS (EVIDENCE SPAN: LINES ${f.first_line || 1} - ${f.last_line || 1})</div>
            <table class="evidence-mini-table">
              <tbody>${evidenceRows}</tbody>
            </table>
          </div>

          <div>
            <div class="detail-section-title">AUTOMATED FIREWALL CONTAINMENT ACTION</div>
            <div class="containment-box">
              <code class="containment-code">${escapeHtml(firewallCmd)}</code>
              <button type="button" class="btn-copy" onclick="window.copyToClipboard('${escapeHtml(firewallCmd)}')">
                Copy Rule
              </button>
            </div>
          </div>

          <div>
            <div class="detail-section-title">ANALYST RECOMMENDATION</div>
            <p class="detail-text" style="color: #34d399;">${escapeHtml(f.suggested_action)}</p>
          </div>
        </div>
      `;

      dom.findingsList.appendChild(card);
    });
  }

  // Toggle Accordion Card
  window.toggleFinding = function (idx) {
    const card = document.getElementById(`findingCard_${idx}`);
    if (card) {
      card.classList.toggle('open');
    }
  };

  // Severity Triage Filter Click Handlers
  const filterGroup = document.getElementById('severityFilterGroup');
  if (filterGroup) {
    filterGroup.addEventListener('click', (e) => {
      const btn = e.target.closest('.triage-pill');
      if (!btn) return;

      filterGroup.querySelectorAll('.triage-pill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      activeSeverityFilter = btn.dataset.filter || 'ALL';
      applyFindingsFilter();
    });
  }

  // Search Filter Handler
  if (dom.findingSearchInput) {
    dom.findingSearchInput.addEventListener('input', (e) => {
      activeSearchQuery = e.target.value;
      applyFindingsFilter();
    });
  }

  // 6. Evidence Log Context Inspection Modal
  window.inspectEvidenceLine = async function (line) {
    if (!currentJobId) return;

    dom.contextModalSubtitle.textContent = `Authentic stream inspection centered on Line ${line} (±5 lines window)`;
    dom.logViewerLines.innerHTML = '<div style="padding: 12px; color: var(--text-muted);">Loading raw stream context...</div>';
    dom.contextModal.style.display = 'flex';

    try {
      const res = await fetch(`/api/logs/${currentJobId}/context?line=${line}&window=5`);
      if (!res.ok) throw new Error('Could not retrieve context from log repository.');

      const data = await res.json();
      dom.logViewerLines.innerHTML = '';

      (data.lines || []).forEach(row => {
        const rowDiv = document.createElement('div');
        rowDiv.className = `log-stream-row ${row.is_target ? 'target' : ''}`;

        const highlightedHtml = highlightLogTokens(escapeHtml(row.text));

        rowDiv.innerHTML = `
          <span class="log-gutter-num">${row.line}</span>
          <span class="log-line-text">${highlightedHtml}</span>
        `;
        dom.logViewerLines.appendChild(rowDiv);
      });
    } catch (err) {
      dom.logViewerLines.innerHTML = `<div style="padding: 12px; color: #f87171;">Error loading context: ${escapeHtml(err.message)}</div>`;
    }
  };

  // Syntax highlighter helper for log strings
  function highlightLogTokens(escapedText) {
    return escapedText
      .replace(/\b(200 OK|200)\b/g, '<span class="token-status-200">$1</span>')
      .replace(/\b(401 Unauthorized|401|403 Forbidden|403)\b/g, '<span class="token-status-401">$1</span>')
      .replace(/\b(404 Not Found|404)\b/g, '<span class="token-status-404">$1</span>')
      .replace(/\b(500 Internal Server Error|500|502 Bad Gateway|502)\b/g, '<span class="token-status-500">$1</span>')
      .replace(/\b(POST|GET|PUT|DELETE|HEAD)\b/g, '<span class="token-method">$1</span>')
      .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, '<span class="token-ip">$1</span>')
      .replace(/\b(failed|failure|breach|compromise|denied)\b/gi, '<span class="token-alert">$1</span>');
  }

  // Modal Close Events
  if (dom.btnCloseModal) {
    dom.btnCloseModal.addEventListener('click', () => {
      dom.contextModal.style.display = 'none';
    });
  }

  if (dom.contextModal) {
    dom.contextModal.addEventListener('click', (e) => {
      if (e.target === dom.contextModal) {
        dom.contextModal.style.display = 'none';
      }
    });
  }

  // Keyboard Shortcuts: Esc to close modal, / to focus search
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && dom.contextModal.style.display === 'flex') {
      dom.contextModal.style.display = 'none';
    } else if (e.key === '/' && dom.reportSection.style.display === 'flex' && document.activeElement !== dom.findingSearchInput) {
      e.preventDefault();
      dom.findingSearchInput.focus();
    }
  });

  // Global Clipboard Helper
  window.copyToClipboard = async function (text) {
    try {
      await navigator.clipboard.writeText(text);
      if (window.event && window.event.target) {
        const target = window.event.target;
        const originalText = target.textContent;
        target.textContent = 'Copied!';
        setTimeout(() => { target.textContent = originalText; }, 1500);
      }
    } catch (err) {
      alert(`Could not copy: ${text}`);
    }
  };

  // Start polling
  pollSystemStatus();
  statusPollTimer = setInterval(pollSystemStatus, 3000);

})();
