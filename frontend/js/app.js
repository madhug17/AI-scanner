/**
 * AI App Security & Quality Scanner — Main Application Controller
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
  compareBaselineId: null,
  compareTargetId: null,
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

  // Update navbar active state
  document.querySelectorAll('.nav-link').forEach(link => {
    if (link.dataset.page === pageId) {
      link.classList.add('text-emerald-400', 'bg-slate-800/60');
      link.classList.remove('text-slate-400');
    } else {
      link.classList.remove('text-emerald-400', 'bg-slate-800/60');
      link.classList.add('text-slate-400');
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
  const bg = type === 'error' ? 'bg-red-950 border-red-800 text-red-200' :
             type === 'success' ? 'bg-emerald-950 border-emerald-800 text-emerald-200' :
             'bg-slate-800 border-slate-700 text-slate-200';

  toast.className = `flex items-center gap-3 px-4 py-3 rounded-lg border shadow-xl text-sm transition-all duration-300 transform translate-y-2 opacity-0 ${bg}`;
  toast.innerHTML = `
    <span>${message}</span>
    <button class="ml-auto text-slate-400 hover:text-white" onclick="this.parentElement.remove()">✕</button>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  }, 10);

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
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

    // Severity pills
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
        tbody.innerHTML = `<tr><td colspan="5" class="py-6 text-center text-slate-500">No scans executed yet. Submit your first repository!</td></tr>`;
      } else {
        tbody.innerHTML = stats.recent_scans.map(s => `
          <tr class="border-b border-slate-800/80 hover:bg-slate-800/30 transition-colors cursor-pointer" onclick="viewScanReport('${s.scan_id}')">
            <td class="py-3 px-4 font-mono text-xs text-slate-300 font-medium">${s.repository_name || s.repository_url}</td>
            <td class="py-3 px-4 text-xs font-semibold ${getRiskColor(s.risk_category)}">${s.risk_score} (${s.risk_category})</td>
            <td class="py-3 px-4 text-xs text-slate-300">${s.findings_count} findings</td>
            <td class="py-3 px-4">
              <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${getStatusBadge(s.status)}">
                ${s.status}
              </span>
            </td>
            <td class="py-3 px-4 text-xs text-slate-400 font-mono">${formatDate(s.created_at)}</td>
          </tr>
        `).join('');
      }
    }
  } catch (err) {
    showToast('Failed to load dashboard statistics: ' + err.message, 'error');
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
        showToast('Scan completed successfully! Loading security report...', 'success');
        setTimeout(() => viewScanReport(scanId), 1000);
      } else if (statusData.status === 'failed' || statusData.status === 'cancelled') {
        clearInterval(state.pollInterval);
        clearInterval(state.elapsedTimer);
        showToast(`Scan ended with status: ${statusData.status}`, 'error');
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
    badge.className = `inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold ${getStatusBadge(status)}`;
  }

  // Highlight stages
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
      dot.className = 'stage-dot w-6 h-6 rounded-full bg-emerald-500/20 border border-emerald-500 text-emerald-400 flex items-center justify-center text-xs font-bold';
      dot.innerHTML = '✓';
      label.className = 'stage-label text-xs font-medium text-slate-200';
    } else if (idx === activeIndex) {
      dot.className = 'stage-dot w-6 h-6 rounded-full bg-emerald-500/30 border-2 border-emerald-400 text-emerald-300 flex items-center justify-center text-xs font-bold pulse-ring';
      dot.innerHTML = '●';
      label.className = 'stage-label text-xs font-bold text-emerald-400';
    } else {
      dot.className = 'stage-dot w-6 h-6 rounded-full bg-slate-800 border border-slate-700 text-slate-500 flex items-center justify-center text-xs';
      dot.innerHTML = String(idx + 1);
      label.className = 'stage-label text-xs text-slate-500';
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
    document.getElementById('report-risk-category').className = `text-sm font-semibold uppercase ${getRiskColor(cat)}`;

    // Risk Meter Bar
    const meterBar = document.getElementById('report-risk-meter');
    if (meterBar) {
      meterBar.style.width = `${Math.min(100, score)}%`;
      meterBar.className = `h-full rounded-full transition-all duration-700 ${getRiskBarColor(cat)}`;
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
    tbody.innerHTML = `<tr><td colspan="6" class="py-12 text-center text-slate-500 font-mono text-sm">No findings match the selected criteria.</td></tr>`;
    return;
  }

  tbody.innerHTML = findings.map((f, idx) => {
    const ev = f.evidence && f.evidence.length > 0 ? f.evidence[0] : null;
    const fileLoc = ev ? `${ev.file_path}:${ev.line_start}` : 'Repository config';
    const sevBadge = getSeverityBadgeClass(f.severity);

    return `
      <tr class="border-b border-slate-800/80 hover:bg-slate-800/40 transition-colors">
        <td class="py-3 px-4">
          <span class="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-semibold ${sevBadge}">
            ${f.severity.toUpperCase()}
          </span>
        </td>
        <td class="py-3 px-4 font-mono text-xs text-slate-300 font-semibold">${f.rule_id}</td>
        <td class="py-3 px-4 text-xs font-medium text-slate-100 max-w-xs truncate">${f.title}</td>
        <td class="py-3 px-4 font-mono text-xs text-slate-400 max-w-xs truncate" title="${fileLoc}">${fileLoc}</td>
        <td class="py-3 px-4 text-xs text-slate-300">${f.category}</td>
        <td class="py-3 px-4 text-right">
          <button class="px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 hover:border-slate-600 transition-colors"
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
  document.getElementById('modal-severity-badge').className = `inline-flex items-center px-2.5 py-0.5 rounded text-xs font-semibold ${getSeverityBadgeClass(f.severity)}`;
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
      <div class="text-xs font-mono text-slate-400 mb-1 flex items-center justify-between">
        <span>${ev.file_path} (Lines ${ev.line_start}-${ev.line_end})</span>
        <span class="text-emerald-400 font-semibold text-[10px]">REDACTED SNIPPET</span>
      </div>
      <pre class="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto"><code>${escapeHtml(ev.code_snippet)}</code></pre>
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
        <div class="col-span-full py-12 text-center text-slate-500 font-mono text-sm">
          No repositories tracked yet. Launch a scan to register your first repository!
        </div>
      `;
      return;
    }

    container.innerHTML = res.items.map(r => `
      <div class="glass-panel p-5 rounded-xl border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between">
        <div>
          <div class="flex items-center justify-between mb-2">
            <span class="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">${r.default_branch}</span>
            <span class="text-xs text-slate-400">${r.is_private ? 'Private' : 'Public'}</span>
          </div>
          <h3 class="text-base font-bold text-slate-100 mb-1 truncate">${r.owner}/${r.name}</h3>
          <p class="text-xs text-slate-400 truncate mb-4">${r.url}</p>
          
          <div class="flex flex-wrap gap-1.5 mb-4">
            ${(r.detected_languages || ['Python']).map(l => `<span class="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/60 text-emerald-300 text-[10px] font-mono">${l}</span>`).join('')}
          </div>
        </div>

        <button class="w-full py-2 px-3 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition-colors flex items-center justify-center gap-1.5"
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

    // Populate comparison dropdowns
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
      tbody.innerHTML = `<tr><td colspan="6" class="py-12 text-center text-slate-500 font-mono text-sm">No historical scans recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = state.historyScans.map(s => `
      <tr class="border-b border-slate-800/80 hover:bg-slate-800/30 transition-colors">
        <td class="py-3 px-4 font-mono text-xs text-slate-300 font-medium">${s.repository_name}</td>
        <td class="py-3 px-4 font-mono text-xs text-slate-400">${s.scan_id}</td>
        <td class="py-3 px-4 font-mono text-xs text-slate-400">${formatDate(s.created_at)}</td>
        <td class="py-3 px-4">
          <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${getStatusBadge(s.status)}">
            ${s.status}
          </span>
        </td>
        <td class="py-3 px-4 text-xs font-mono text-slate-300">${s.scan_version || '1.0.0'}</td>
        <td class="py-3 px-4 text-right">
          <button class="px-2.5 py-1 text-xs font-medium rounded bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/30 transition-colors"
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
      newFindingsList.innerHTML = `<p class="text-xs text-slate-500 italic">No new vulnerabilities introduced.</p>`;
    } else {
      newFindingsList.innerHTML = diff.new_findings.map(f => `
        <div class="p-2.5 rounded bg-red-950/30 border border-red-900/50 flex items-center justify-between text-xs">
          <span class="font-mono font-bold text-red-400">${f.rule_id}</span>
          <span class="text-slate-200 truncate mx-2">${f.title}</span>
          <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold ${getSeverityBadgeClass(f.severity)}">${f.severity.toUpperCase()}</span>
        </div>
      `).join('');
    }

    // Render resolved findings
    const resolvedList = document.getElementById('diff-resolved-findings-list');
    if (diff.resolved_findings.length === 0) {
      resolvedList.innerHTML = `<p class="text-xs text-slate-500 italic">No previous vulnerabilities resolved.</p>`;
    } else {
      resolvedList.innerHTML = diff.resolved_findings.map(f => `
        <div class="p-2.5 rounded bg-emerald-950/30 border border-emerald-900/50 flex items-center justify-between text-xs">
          <span class="font-mono font-bold text-emerald-400">${f.rule_id}</span>
          <span class="text-slate-200 truncate mx-2">${f.title}</span>
          <span class="text-emerald-400 font-semibold text-[10px]">RESOLVED</span>
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

  // Update button active state
  document.querySelectorAll('.rule-cat-btn').forEach(b => {
    b.classList.remove('bg-emerald-600', 'text-white');
    b.classList.add('bg-slate-800', 'text-slate-400');
  });
  if (btnElement) {
    btnElement.classList.add('bg-emerald-600', 'text-white');
    btnElement.classList.remove('bg-slate-800', 'text-slate-400');
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
    container.innerHTML = `<div class="col-span-full py-12 text-center text-slate-500 font-mono text-sm">No rules matching search.</div>`;
    return;
  }

  container.innerHTML = filtered.map(r => `
    <div class="glass-panel p-5 rounded-xl border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between mb-2">
          <span class="font-mono text-xs font-bold text-emerald-400 px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/60">${r.id}</span>
          <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${getSeverityBadgeClass(r.severity)}">${r.severity.toUpperCase()}</span>
        </div>
        <h4 class="text-sm font-bold text-slate-100 mb-1">${r.title}</h4>
        <span class="text-[11px] font-mono text-slate-400 block mb-2">${r.category}</span>
        <p class="text-xs text-slate-300 leading-relaxed mb-3">${r.description}</p>
      </div>
      <div class="pt-3 border-t border-slate-800/80">
        <span class="text-[10px] text-slate-500 font-mono uppercase block mb-1">Recommended Solution:</span>
        <p class="text-xs text-emerald-300/90 leading-tight">${r.recommendation}</p>
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
          <div class="w-10 h-10 rounded-full bg-emerald-600/30 border border-emerald-500 text-emerald-300 flex items-center justify-center font-bold">
            ${(user.full_name || user.email)[0].toUpperCase()}
          </div>
          <div>
            <div class="text-sm font-bold text-white">${user.full_name || 'Authenticated Developer'}</div>
            <div class="text-xs text-slate-400">${user.email}</div>
          </div>
          <button class="ml-auto text-xs px-3 py-1.5 rounded bg-red-950/60 text-red-300 border border-red-800/60 hover:bg-red-900/60" onclick="logoutUser()">Logout</button>
        </div>
      `;
    } else {
      profileEl.innerHTML = `
        <div class="flex items-center justify-between">
          <span class="text-xs text-slate-400">Not authenticated. Running in local development mode.</span>
          <button class="text-xs px-3 py-1.5 rounded bg-emerald-600 text-white font-semibold hover:bg-emerald-500" onclick="openAuthModal()">Sign In / Register</button>
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
    showToast('Please enter both email and password', 'error');
    return;
  }

  try {
    if (isRegister) {
      await window.api.register(email, password, name);
      showToast('Registration successful!', 'success');
    } else {
      await window.api.login(email, password);
      showToast('Signed in successfully!', 'success');
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
    case 'completed': return 'bg-emerald-950/80 text-emerald-300 border border-emerald-800';
    case 'scanning': return 'bg-yellow-950/80 text-yellow-300 border border-yellow-800 animate-pulse';
    case 'cloning': return 'bg-blue-950/80 text-blue-300 border border-blue-800';
    case 'queued': return 'bg-slate-800 text-slate-300 border border-slate-700';
    case 'failed': return 'bg-red-950/80 text-red-300 border border-red-800';
    default: return 'bg-slate-800 text-slate-400';
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
    case 'critical': return 'text-red-400';
    case 'high': return 'text-orange-400';
    case 'medium': return 'text-yellow-400';
    case 'low': return 'text-blue-400';
    default: return 'text-emerald-400';
  }
}

function getRiskBarColor(cat) {
  switch ((cat || '').toLowerCase()) {
    case 'critical': return 'bg-red-500 shadow-[0_0_12px_rgba(239,68,68,0.5)]';
    case 'high': return 'bg-orange-500 shadow-[0_0_12px_rgba(249,115,22,0.5)]';
    case 'medium': return 'bg-yellow-500 shadow-[0_0_12px_rgba(245,158,11,0.5)]';
    case 'low': return 'bg-blue-500 shadow-[0_0_12px_rgba(59,130,246,0.5)]';
    default: return 'bg-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.5)]';
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

  // Filter events on results page
  document.getElementById('findings-search')?.addEventListener('input', (e) => {
    state.findingsFilter.search = e.target.value.trim();
    renderFindingsTable();
  });

  document.getElementById('filter-category-select')?.addEventListener('change', (e) => {
    state.findingsFilter.category = e.target.value;
    renderFindingsTable();
  });

  // Severity pill buttons on results page
  document.querySelectorAll('.filter-sev-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const sev = btn.dataset.severity;
      state.findingsFilter.severity = sev;
      document.querySelectorAll('.filter-sev-btn').forEach(b => b.classList.remove('ring-2', 'ring-emerald-400'));
      btn.classList.add('ring-2', 'ring-emerald-400');
      renderFindingsTable();
    });
  });

  // Rules search
  document.getElementById('rules-search-input')?.addEventListener('input', () => {
    renderRulesGrid();
  });

  // Default start on landing page
  navigateTo('landing-page');
});
