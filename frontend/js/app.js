/**
 * AI App Security & Quality Scanner — Main Application Controller
 * Premium Minimalist Architecture (Clean, simple, no neon)
 */

// Application State
const state = {
  currentPage: 'landing-page',
  currentScanId: null,
  currentScanReport: null,
  currentRepoId: null,
  pollInterval: null,
  scanStartTime: null,
  elapsedTimer: null,
  findingsFilter: {
    severity: 'all',
    category: 'all',
    search: '',
    sort: 'severity-desc',
    page: 1,
    pageSize: 15,
  },
  allRules: [],
  selectedRuleCategory: 'all',
  historyScans: [],
  currentUser: null,
};

// Navigation
function navigateTo(pageId) {
  state.currentPage = pageId;

  // Hide all pages
  document.querySelectorAll('.app-page').forEach(p => p.classList.add('hidden'));

  // Show target page
  const target = document.getElementById(pageId);
  if (target) {
    target.classList.remove('hidden');
  }

  // Update navbar active state (clean, subtle contrast)
  document.querySelectorAll('.nav-link').forEach(link => {
    if (link.dataset.page === pageId) {
      link.classList.add('text-[#f0f6fc]', 'bg-[#21262d]');
      link.classList.remove('text-[#8b949e]');
    } else {
      link.classList.remove('text-[#f0f6fc]', 'bg-[#21262d]');
      link.classList.add('text-[#8b949e]');
    }
  });

  // Page specific initialization
  if (pageId === 'dashboard-page') {
    loadDashboardData();
  } else if (pageId === 'history-page') {
    loadScanHistory();
  } else if (pageId === 'rules-page') {
    loadRulesCatalog();
  } else if (pageId === 'repo-details-page') {
    loadRepositoriesList();
  } else if (pageId === 'settings-page') {
    loadSettingsPage();
  }

  if (window.lucide) {
    window.lucide.createIcons();
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Notifications / Toasts
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  const bg = type === 'error' ? 'bg-[#21262d] border-[#f85149]/50 text-[#f85149]' :
             type === 'success' ? 'bg-[#21262d] border-[#238636]/60 text-[#3fb950]' :
             'bg-[#21262d] border-[#30363d] text-[#c9d1d9]';

  toast.className = `flex items-center gap-3 px-4 py-3 rounded-md border shadow-lg text-xs font-medium transition-all duration-200 transform translate-y-2 opacity-0 ${bg}`;
  toast.innerHTML = `
    <span>${message}</span>
    <button class="ml-auto text-[#8b949e] hover:text-white" onclick="this.parentElement.remove()">✕</button>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  }, 10);

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

// --- 1. Landing Page Actions ---
function initLandingPage() {
  const heroForm = document.getElementById('hero-scan-form');
  if (heroForm) {
    heroForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = document.getElementById('hero-repo-input');
      const url = input ? input.value.trim() : '';
      if (!url) {
        showToast('Please enter a valid GitHub repository URL', 'error');
        return;
      }
      await initiateScan(url);
    });
  }
}

// --- 2. Dashboard Page ---
async function loadDashboardData() {
  try {
    const stats = await window.api.getDashboardStats();

    // Metric numbers
    document.getElementById('stat-total-repos').textContent = stats.total_repositories || 0;
    document.getElementById('stat-total-vulns').textContent = stats.total_vulnerabilities || 0;
    document.getElementById('stat-total-scans').textContent = stats.total_scans || 0;
    document.getElementById('stat-success-rate').textContent = `${stats.success_rate_pct || 100}%`;

    // Severity counts
    const sev = stats.severity_distribution || {};
    document.getElementById('pill-crit-count').textContent = sev.critical || 0;
    document.getElementById('pill-high-count').textContent = sev.high || 0;
    document.getElementById('pill-med-count').textContent = sev.medium || 0;
    document.getElementById('pill-low-count').textContent = (sev.low || 0) + (sev.info || 0);

    // Charts
    window.charts.renderSeverityChart('dashboard-severity-chart', sev);
    window.charts.renderCategoryChart('dashboard-category-chart', stats.category_distribution || {});

    // Recent Scans Table
    const tbody = document.getElementById('dashboard-recent-scans');
    if (tbody) {
      if (!stats.recent_scans || stats.recent_scans.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="py-8 text-center text-[#8b949e] font-mono text-xs">No repository scans recorded yet.</td></tr>`;
      } else {
        tbody.innerHTML = stats.recent_scans.map(s => `
          <tr class="border-b border-[#21262d] hover:bg-[#1c2128] transition-colors cursor-pointer" onclick="viewScanReport('${s.scan_id}')">
            <td class="py-3 px-4 font-mono text-xs text-[#c9d1d9] font-medium">${s.repository_name || s.repository_url}</td>
            <td class="py-3 px-4 text-xs font-semibold ${getRiskColor(s.risk_category)}">${s.risk_score} (${s.risk_category})</td>
            <td class="py-3 px-4 text-xs text-[#8b949e]">${s.findings_count} findings</td>
            <td class="py-3 px-4">
              <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium ${getStatusBadge(s.status)}">
                ${s.status}
              </span>
            </td>
            <td class="py-3 px-4 text-xs text-[#6e7681] font-mono">${formatDate(s.created_at)}</td>
          </tr>
        `).join('');
      }
    }
  } catch (err) {
    showToast('Failed to load dashboard data: ' + err.message, 'error');
  }
}

// --- 3. New Scan Page ---
function initNewScanPage() {
  const form = document.getElementById('new-scan-form');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = document.getElementById('new-scan-url');
      const url = input ? input.value.trim() : '';
      if (!url) {
        showToast('Please provide a valid GitHub repository URL', 'error');
        return;
      }
      await initiateScan(url);
    });
  }
}

async function initiateScan(repositoryUrl) {
  try {
    showToast('Submitting repository to scanning pipeline...', 'info');
    const result = await window.api.submitScan(repositoryUrl);
    if (!result.scan_id) {
      throw new Error('No scan ID returned by backend');
    }

    state.currentScanId = result.scan_id;
    startScanProgress(result.scan_id, repositoryUrl);
  } catch (err) {
    showToast('Failed to start scan: ' + err.message, 'error');
  }
}

// --- 4. Live Scan Progress Page ---
function startScanProgress(scanId, repositoryUrl) {
  state.currentScanId = scanId;
  state.scanStartTime = Date.now();
  navigateTo('scan-progress-page');

  document.getElementById('progress-scan-id').textContent = scanId;
  document.getElementById('progress-repo-url').textContent = repositoryUrl;

  // Start elapsed timer
  if (state.elapsedTimer) clearInterval(state.elapsedTimer);
  state.elapsedTimer = setInterval(() => {
    const elapsedSec = Math.floor((Date.now() - state.scanStartTime) / 1000);
    const mins = String(Math.floor(elapsedSec / 60)).padStart(2, '0');
    const secs = String(elapsedSec % 60).padStart(2, '0');
    document.getElementById('progress-elapsed').textContent = `${mins}:${secs}s`;
  }, 1000);

  // Poll status every 1.5s
  if (state.pollInterval) clearInterval(state.pollInterval);
  state.pollInterval = setInterval(async () => {
    try {
      const statusData = await window.api.getScanStatus(scanId);
      updateProgressUI(statusData.status);

      if (statusData.status === 'completed') {
        clearInterval(state.pollInterval);
        clearInterval(state.elapsedTimer);
        showToast('Scan completed. Loading security report...', 'success');
        setTimeout(() => viewScanReport(scanId), 800);
      } else if (statusData.status === 'failed' || statusData.status === 'cancelled') {
        clearInterval(state.pollInterval);
        clearInterval(state.elapsedTimer);
        showToast(`Scan finished with status: ${statusData.status}`, 'error');
      }
    } catch (err) {
      console.warn('Polling error:', err);
    }
  }, 1500);
}

function updateProgressUI(status) {
  const badge = document.getElementById('progress-status-badge');
  if (badge) {
    badge.textContent = status.toUpperCase();
    badge.className = `inline-flex items-center px-2.5 py-0.5 rounded text-xs font-semibold ${getStatusBadge(status)}`;
  }

  const stages = [
    'stage-validation',
    'stage-acquisition',
    'stage-structure',
    'stage-secrets',
    'stage-static',
    'stage-dependencies',
    'stage-docker',
    'stage-ai',
    'stage-normalization',
    'stage-report',
  ];

  let activeIndex = 0;
  if (status === 'queued') activeIndex = 1;
  else if (status === 'cloning') activeIndex = 2;
  else if (status === 'scanning') activeIndex = 6;
  else if (status === 'processing') activeIndex = 8;
  else if (status === 'completed') activeIndex = 10;

  stages.forEach((id, idx) => {
    const el = document.getElementById(id);
    if (!el) return;
    const dot = el.querySelector('.stage-dot');
    const label = el.querySelector('.stage-label');

    if (idx < activeIndex) {
      dot.className = 'stage-dot w-5 h-5 rounded-full bg-[#161b22] border border-[#238636] text-[#3fb950] flex items-center justify-center text-[10px] font-bold';
      dot.innerHTML = '✓';
      label.className = 'stage-label text-xs text-[#c9d1d9]';
    } else if (idx === activeIndex) {
      dot.className = 'stage-dot w-5 h-5 rounded-full bg-[#161b22] border-2 border-[#58a6ff] text-[#58a6ff] flex items-center justify-center text-[10px] font-bold';
      dot.innerHTML = '●';
      label.className = 'stage-label text-xs font-semibold text-[#f0f6fc]';
    } else {
      dot.className = 'stage-dot w-5 h-5 rounded-full bg-[#161b22] border border-[#30363d] text-[#6e7681] flex items-center justify-center text-[10px] font-mono';
      dot.innerHTML = String(idx + 1);
      label.className = 'stage-label text-xs text-[#6e7681]';
    }
  });
}

// --- 5. Scan Results Page ---
async function viewScanReport(scanId) {
  try {
    state.currentScanId = scanId;
    navigateTo('scan-results-page');

    const report = await window.api.getScanReport(scanId);
    state.currentScanReport = report;

    // Header info
    document.getElementById('report-repo-url').textContent = report.repository_url;
    document.getElementById('report-scan-id').textContent = report.scan_id;
    document.getElementById('report-timestamp').textContent = formatDate(report.created_at);
    document.getElementById('report-duration').textContent = report.completed_at ? 'Completed' : 'Running';

    // Risk Card
    const score = report.summary ? report.summary.risk_score : 0.0;
    const cat = report.summary ? report.summary.risk_category : 'Clean';
    document.getElementById('report-risk-score').textContent = score;
    document.getElementById('report-risk-category').textContent = `${cat} Risk`;
    document.getElementById('report-risk-category').className = `text-xs font-semibold uppercase ${getRiskColor(cat)}`;

    // Risk Meter Bar
    const meterBar = document.getElementById('report-risk-meter');
    if (meterBar) {
      meterBar.style.width = `${Math.min(100, score)}%`;
      meterBar.className = `h-full rounded-full transition-all duration-500 ${getRiskBarColor(cat)}`;
    }

    // Counters
    document.getElementById('report-total-findings').textContent = report.findings.length;
    document.getElementById('count-crit').textContent = report.summary ? report.summary.critical_count : 0;
    document.getElementById('count-high').textContent = report.summary ? report.summary.high_count : 0;
    document.getElementById('count-med').textContent = report.summary ? report.summary.medium_count : 0;
    document.getElementById('count-low').textContent = report.summary ? (report.summary.low_count + report.summary.info_count) : 0;

    // Download Links
    document.getElementById('btn-download-json').onclick = () => {
      window.open(`/api/v1/scans/${scanId}/report/json`, '_blank');
    };
    document.getElementById('btn-download-pdf').onclick = () => {
      window.open(`/api/v1/scans/${scanId}/report/pdf`, '_blank');
    };

    // Render findings
    renderFindingsTable();
  } catch (err) {
    showToast('Failed to load scan report: ' + err.message, 'error');
  }
}

function renderFindingsTable() {
  if (!state.currentScanReport) return;
  const tbody = document.getElementById('findings-table-body');
  if (!tbody) return;

  let findings = [...state.currentScanReport.findings];

  // Severity filter
  if (state.findingsFilter.severity !== 'all') {
    findings = findings.filter(f => f.severity.toLowerCase() === state.findingsFilter.severity.toLowerCase());
  }

  // Category filter
  if (state.findingsFilter.category !== 'all') {
    findings = findings.filter(f => f.category === state.findingsFilter.category);
  }

  // Search filter
  if (state.findingsFilter.search) {
    const q = state.findingsFilter.search.toLowerCase();
    findings = findings.filter(f => 
      f.title.toLowerCase().includes(q) ||
      f.rule_id.toLowerCase().includes(q) ||
      f.description.toLowerCase().includes(q) ||
      (f.evidence && f.evidence.some(e => e.file_path.toLowerCase().includes(q)))
    );
  }

  // Populate category filter dropdown dynamically
  const categories = [...new Set(state.currentScanReport.findings.map(f => f.category))];
  const catSelect = document.getElementById('filter-category-select');
  if (catSelect && catSelect.children.length <= 1) {
    categories.forEach(cat => {
      const opt = document.createElement('option');
      opt.value = cat;
      opt.textContent = cat;
      catSelect.appendChild(opt);
    });
  }

  // Total match count
  document.getElementById('findings-match-count').textContent = `${findings.length} findings matching filters`;

  if (findings.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="py-10 text-center text-[#8b949e] font-mono text-xs">No findings match the selected criteria.</td></tr>`;
    return;
  }

  tbody.innerHTML = findings.map((f, idx) => {
    const ev = f.evidence && f.evidence.length > 0 ? f.evidence[0] : null;
    const fileLoc = ev ? `${ev.file_path}:${ev.line_start}` : 'Repository config';
    const sevBadge = getSeverityBadgeClass(f.severity);

    return `
      <tr class="border-b border-[#21262d] hover:bg-[#1c2128] transition-colors">
        <td class="py-3 px-4">
          <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold ${sevBadge}">
            ${f.severity.toUpperCase()}
          </span>
        </td>
        <td class="py-3 px-4 font-mono text-xs text-[#c9d1d9] font-medium">${f.rule_id}</td>
        <td class="py-3 px-4 text-xs font-medium text-[#f0f6fc] max-w-xs truncate">${f.title}</td>
        <td class="py-3 px-4 font-mono text-xs text-[#8b949e] max-w-xs truncate" title="${fileLoc}">${fileLoc}</td>
        <td class="py-3 px-4 text-xs text-[#8b949e]">${f.category}</td>
        <td class="py-3 px-4 text-right">
          <button class="btn-secondary px-2.5 py-1 text-xs rounded transition-colors"
                  onclick="openFindingDetailModal(${idx})">
            Inspect
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

// Finding Detail Modal
function openFindingDetailModal(index) {
  if (!state.currentScanReport) return;
  const f = state.currentScanReport.findings[index];
  if (!f) return;

  const modal = document.getElementById('finding-detail-modal');
  if (!modal) return;

  document.getElementById('modal-rule-id').textContent = f.rule_id;
  document.getElementById('modal-severity-badge').textContent = f.severity.toUpperCase();
  document.getElementById('modal-severity-badge').className = `inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${getSeverityBadgeClass(f.severity)}`;
  document.getElementById('modal-title').textContent = f.title;
  document.getElementById('modal-category').textContent = f.category;
  document.getElementById('modal-confidence').textContent = f.confidence || 'High';
  document.getElementById('modal-status').textContent = f.status || 'Confirmed';
  document.getElementById('modal-description').textContent = f.description;
  document.getElementById('modal-impact').textContent = f.impact;
  document.getElementById('modal-recommendation').textContent = f.recommendation;

  const evContainer = document.getElementById('modal-evidence-container');
  if (f.evidence && f.evidence.length > 0) {
    const ev = f.evidence[0];
    evContainer.innerHTML = `
      <div class="text-[11px] font-mono text-[#8b949e] mb-1 flex items-center justify-between">
        <span>${ev.file_path} (Lines ${ev.line_start}-${ev.line_end})</span>
        <span class="text-[#8b949e] font-semibold text-[10px]">REDACTED SNIPPET</span>
      </div>
      <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9] overflow-x-auto"><code>${escapeHtml(ev.code_snippet)}</code></pre>
    `;
    evContainer.classList.remove('hidden');
  } else {
    evContainer.classList.add('hidden');
  }

  modal.classList.remove('hidden');
}

function closeFindingDetailModal() {
  const modal = document.getElementById('finding-detail-modal');
  if (modal) modal.classList.add('hidden');
}

// --- 6. Repository Details Page ---
async function loadRepositoriesList() {
  try {
    const res = await window.api.listRepositories(1, 20);
    const container = document.getElementById('repos-grid');
    if (!container) return;

    if (!res.items || res.items.length === 0) {
      container.innerHTML = `
        <div class="col-span-full py-12 text-center text-[#8b949e] font-mono text-xs">
          No repositories tracked yet. Launch a scan to register your first repository.
        </div>
      `;
      return;
    }

    container.innerHTML = res.items.map(r => `
      <div class="surface-card surface-card-hover p-5 rounded-lg flex flex-col justify-between">
        <div>
          <div class="flex items-center justify-between mb-2">
            <span class="font-mono text-[11px] px-2 py-0.5 rounded bg-[#21262d] text-[#c9d1d9]">${r.default_branch}</span>
            <span class="text-[11px] text-[#6e7681]">${r.is_private ? 'Private' : 'Public'}</span>
          </div>
          <h3 class="text-sm font-semibold text-[#f0f6fc] mb-1 truncate">${r.owner}/${r.name}</h3>
          <p class="text-xs text-[#8b949e] truncate mb-4 font-mono">${r.url}</p>
          
          <div class="flex flex-wrap gap-1.5 mb-4">
            ${(r.detected_languages || ['Python']).map(l => `<span class="px-2 py-0.5 rounded bg-[#21262d] border border-[#30363d] text-[#c9d1d9] text-[10px] font-mono">${l}</span>`).join('')}
          </div>
        </div>

        <button class="btn-primary w-full py-2 px-3 text-xs rounded transition-colors flex items-center justify-center gap-1.5"
                onclick="initiateScan('${r.url}')">
          Scan Now
        </button>
      </div>
    `).join('');
  } catch (err) {
    showToast('Failed to load repositories: ' + err.message, 'error');
  }
}

// --- 7. Scan History Page & Comparison ---
async function loadScanHistory() {
  try {
    const res = await window.api.listScans(1, 50);
    state.historyScans = res.items || [];

    const tbody = document.getElementById('history-table-body');
    if (!tbody) return;

    const selectA = document.getElementById('compare-scan-a');
    const selectB = document.getElementById('compare-scan-b');
    if (selectA && selectB) {
      const options = state.historyScans.map(s => `
        <option value="${s.scan_id}">${s.repository_name} (${formatDate(s.created_at)}) - ${s.scan_id.substring(0, 8)}</option>
      `).join('');
      selectA.innerHTML = '<option value="">Select Baseline Scan</option>' + options;
      selectB.innerHTML = '<option value="">Select Target Scan</option>' + options;
    }

    if (state.historyScans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="py-10 text-center text-[#8b949e] font-mono text-xs">No historical scans recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = state.historyScans.map(s => `
      <tr class="border-b border-[#21262d] hover:bg-[#1c2128] transition-colors">
        <td class="py-3 px-4 font-mono text-xs text-[#c9d1d9] font-medium">${s.repository_name}</td>
        <td class="py-3 px-4 font-mono text-xs text-[#8b949e]">${s.scan_id}</td>
        <td class="py-3 px-4 font-mono text-xs text-[#6e7681]">${formatDate(s.created_at)}</td>
        <td class="py-3 px-4">
          <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium ${getStatusBadge(s.status)}">
            ${s.status}
          </span>
        </td>
        <td class="py-3 px-4 text-xs font-mono text-[#8b949e]">${s.scan_version || '1.0.0'}</td>
        <td class="py-3 px-4 text-right">
          <button class="btn-secondary px-2.5 py-1 text-xs rounded transition-colors"
                  onclick="viewScanReport('${s.scan_id}')">
            View Report
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    showToast('Failed to load scan history: ' + err.message, 'error');
  }
}

async function runScanComparison() {
  const scanA = document.getElementById('compare-scan-a').value;
  const scanB = document.getElementById('compare-scan-b').value;

  if (!scanA || !scanB) {
    showToast('Please select two distinct scans to compare', 'error');
    return;
  }
  if (scanA === scanB) {
    showToast('Cannot compare a scan with itself', 'error');
    return;
  }

  try {
    const diff = await window.api.compareScans(scanA, scanB);
    const container = document.getElementById('compare-results-container');
    if (!container) return;

    container.classList.remove('hidden');

    document.getElementById('diff-new-count').textContent = diff.new_count;
    document.getElementById('diff-resolved-count').textContent = diff.resolved_count;
    document.getElementById('diff-persistent-count').textContent = diff.persistent_count;
    document.getElementById('diff-score-delta').textContent = `${diff.risk_score_delta > 0 ? '+' : ''}${diff.risk_score_delta}`;

    // Render new findings
    const newFindingsList = document.getElementById('diff-new-findings-list');
    if (diff.new_findings.length === 0) {
      newFindingsList.innerHTML = `<p class="text-xs text-[#8b949e] italic">No new vulnerabilities introduced.</p>`;
    } else {
      newFindingsList.innerHTML = diff.new_findings.map(f => `
        <div class="p-2.5 rounded bg-[#161b22] border border-[#f85149]/20 flex items-center justify-between text-xs">
          <span class="font-mono font-semibold text-[#f85149]">${f.rule_id}</span>
          <span class="text-[#c9d1d9] truncate mx-2">${f.title}</span>
          <span class="px-1.5 py-0.2 rounded text-[10px] font-semibold ${getSeverityBadgeClass(f.severity)}">${f.severity.toUpperCase()}</span>
        </div>
      `).join('');
    }

    // Render resolved findings
    const resolvedList = document.getElementById('diff-resolved-findings-list');
    if (diff.resolved_findings.length === 0) {
      resolvedList.innerHTML = `<p class="text-xs text-[#8b949e] italic">No previous vulnerabilities resolved.</p>`;
    } else {
      resolvedList.innerHTML = diff.resolved_findings.map(f => `
        <div class="p-2.5 rounded bg-[#161b22] border border-[#238636]/30 flex items-center justify-between text-xs">
          <span class="font-mono font-semibold text-[#3fb950]">${f.rule_id}</span>
          <span class="text-[#c9d1d9] truncate mx-2">${f.title}</span>
          <span class="text-[#3fb950] font-semibold text-[10px]">RESOLVED</span>
        </div>
      `).join('');
    }
  } catch (err) {
    showToast('Failed to compare scans: ' + err.message, 'error');
  }
}

// --- 8. Security Rules Catalog Page ---
async function loadRulesCatalog() {
  try {
    const res = await window.api.getRules();
    state.allRules = res.rules || [];

    document.getElementById('rules-total-count').textContent = `${state.allRules.length} Registered Security Rules`;

    renderRulesGrid();
  } catch (err) {
    showToast('Failed to load rules catalog: ' + err.message, 'error');
  }
}

function filterRulesByCategory(category, btnElement) {
  state.selectedRuleCategory = category;

  document.querySelectorAll('.rule-cat-btn').forEach(b => {
    b.classList.remove('bg-[#21262d]', 'text-[#f0f6fc]', 'border-[#8b949e]');
    b.classList.add('bg-[#161b22]', 'text-[#8b949e]', 'border-[#30363d]');
  });
  if (btnElement) {
    btnElement.classList.add('bg-[#21262d]', 'text-[#f0f6fc]', 'border-[#8b949e]');
    btnElement.classList.remove('bg-[#161b22]', 'text-[#8b949e]', 'border-[#30363d]');
  }

  renderRulesGrid();
}

function renderRulesGrid() {
  const container = document.getElementById('rules-grid');
  if (!container) return;

  const search = (document.getElementById('rules-search-input')?.value || '').toLowerCase();

  let filtered = [...state.allRules];

  if (state.selectedRuleCategory !== 'all') {
    filtered = filtered.filter(r => r.category.toLowerCase().includes(state.selectedRuleCategory.toLowerCase()));
  }

  if (search) {
    filtered = filtered.filter(r => 
      r.id.toLowerCase().includes(search) ||
      r.title.toLowerCase().includes(search) ||
      r.description.toLowerCase().includes(search)
    );
  }

  if (filtered.length === 0) {
    container.innerHTML = `<div class="col-span-full py-12 text-center text-[#8b949e] font-mono text-xs">No rules match the search term.</div>`;
    return;
  }

  container.innerHTML = filtered.map(r => `
    <div class="surface-card surface-card-hover p-4 rounded-lg flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between mb-2">
          <span class="font-mono text-xs font-semibold text-[#f0f6fc] px-2 py-0.5 rounded bg-[#21262d] border border-[#30363d]">${r.id}</span>
          <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${getSeverityBadgeClass(r.severity)}">${r.severity.toUpperCase()}</span>
        </div>
        <h4 class="text-xs font-semibold text-[#f0f6fc] mb-1">${r.title}</h4>
        <span class="text-[11px] font-mono text-[#8b949e] block mb-2">${r.category}</span>
        <p class="text-xs text-[#c9d1d9] leading-relaxed mb-3">${r.description}</p>
      </div>
      <div class="pt-3 border-t border-[#21262d]">
        <span class="text-[10px] text-[#6e7681] font-mono uppercase block mb-0.5">Solution:</span>
        <p class="text-xs text-[#8b949e]">${r.recommendation}</p>
      </div>
    </div>
  `).join('');
}

// --- 9. Settings Page ---
async function loadSettingsPage() {
  const user = await window.api.getCurrentUser();
  state.currentUser = user;

  const profileEl = document.getElementById('settings-profile-status');
  if (profileEl) {
    if (user) {
      profileEl.innerHTML = `
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-full bg-[#21262d] border border-[#30363d] text-[#f0f6fc] flex items-center justify-center font-semibold text-xs">
            ${(user.full_name || user.email)[0].toUpperCase()}
          </div>
          <div>
            <div class="text-xs font-semibold text-[#f0f6fc]">${user.full_name || 'Developer'}</div>
            <div class="text-[11px] text-[#8b949e]">${user.email}</div>
          </div>
          <button class="ml-auto text-xs px-2.5 py-1 rounded bg-[#21262d] text-[#f85149] border border-[#30363d] hover:border-[#f85149]/40" onclick="logoutUser()">Logout</button>
        </div>
      `;
    } else {
      profileEl.innerHTML = `
        <div class="flex items-center justify-between">
          <span class="text-xs text-[#8b949e]">Local mode (Unauthenticated)</span>
          <button class="btn-secondary text-xs px-3 py-1.5 rounded" onclick="openAuthModal()">Sign In / Register</button>
        </div>
      `;
    }
  }
}

function openAuthModal() {
  document.getElementById('auth-modal')?.classList.remove('hidden');
}

function closeAuthModal() {
  document.getElementById('auth-modal')?.classList.add('hidden');
}

async function handleAuthSubmit(isRegister = false) {
  const email = document.getElementById('auth-email').value.trim();
  const password = document.getElementById('auth-password').value.trim();
  const name = document.getElementById('auth-name')?.value.trim();

  if (!email || !password) {
    showToast('Please enter email and password', 'error');
    return;
  }

  try {
    if (isRegister) {
      await window.api.register(email, password, name);
      showToast('Registration successful', 'success');
    } else {
      await window.api.login(email, password);
      showToast('Signed in', 'success');
    }
    closeAuthModal();
    loadSettingsPage();
  } catch (err) {
    showToast('Authentication failed: ' + err.message, 'error');
  }
}

function logoutUser() {
  window.api.logout();
  showToast('Logged out', 'info');
  loadSettingsPage();
}

// Utility Helpers
function getStatusBadge(status) {
  switch (status.toLowerCase()) {
    case 'completed': return 'bg-[#161b22] text-[#3fb950] border border-[#238636]/40';
    case 'scanning': return 'bg-[#161b22] text-[#e3b341] border border-[#d29922]/40';
    case 'cloning': return 'bg-[#161b22] text-[#58a6ff] border border-[#388bfd]/40';
    case 'queued': return 'bg-[#161b22] text-[#8b949e] border border-[#30363d]';
    case 'failed': return 'bg-[#161b22] text-[#f85149] border border-[#f85149]/40';
    default: return 'bg-[#161b22] text-[#8b949e] border border-[#30363d]';
  }
}

function getSeverityBadgeClass(sev) {
  switch (sev.toLowerCase()) {
    case 'critical': return 'badge-critical';
    case 'high': return 'badge-high';
    case 'medium': return 'badge-medium';
    case 'low': return 'badge-low';
    default: return 'badge-info';
  }
}

function getRiskColor(cat) {
  switch ((cat || '').toLowerCase()) {
    case 'critical': return 'text-[#f85149]';
    case 'high': return 'text-[#f0883e]';
    case 'medium': return 'text-[#d29922]';
    case 'low': return 'text-[#58a6ff]';
    default: return 'text-[#3fb950]';
  }
}

function getRiskBarColor(cat) {
  switch ((cat || '').toLowerCase()) {
    case 'critical': return 'bg-[#f85149]';
    case 'high': return 'bg-[#f0883e]';
    case 'medium': return 'bg-[#d29922]';
    case 'low': return 'bg-[#58a6ff]';
    default: return 'bg-[#238636]';
  }
}

function formatDate(iso) {
  if (!iso) return 'N/A';
  try {
    const d = new Date(iso);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return iso;
  }
}

function escapeHtml(str) {
  return (str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Global Initialization
document.addEventListener('DOMContentLoaded', () => {
  initLandingPage();
  initNewScanPage();

  document.getElementById('findings-search')?.addEventListener('input', (e) => {
    state.findingsFilter.search = e.target.value.trim();
    renderFindingsTable();
  });

  document.getElementById('filter-category-select')?.addEventListener('change', (e) => {
    state.findingsFilter.category = e.target.value;
    renderFindingsTable();
  });

  document.querySelectorAll('.filter-sev-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const sev = btn.dataset.severity;
      state.findingsFilter.severity = sev;
      document.querySelectorAll('.filter-sev-btn').forEach(b => b.classList.remove('border-[#58a6ff]'));
      btn.classList.add('border-[#58a6ff]');
      renderFindingsTable();
    });
  });

  document.getElementById('rules-search-input')?.addEventListener('input', () => {
    renderRulesGrid();
  });

  navigateTo('landing-page');
});
