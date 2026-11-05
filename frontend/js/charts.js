/**
 * AI App Security & Quality Scanner — Charts Controller
 */

let severityChartInstance = null;
let categoryChartInstance = null;

function renderSeverityChart(canvasId, severityCounts) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  if (severityChartInstance) {
    severityChartInstance.destroy();
  }

  const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const data = [
    severityCounts.critical || 0,
    severityCounts.high || 0,
    severityCounts.medium || 0,
    severityCounts.low || 0,
    severityCounts.info || 0,
  ];

  const total = data.reduce((a, b) => a + b, 0);

  severityChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: total === 0 ? [1] : data,
        backgroundColor: total === 0 ? ['#334155'] : ['#ef4444', '#f97316', '#f59e0b', '#3b82f6', '#64748b'],
        borderWidth: 2,
        borderColor: '#0f172a',
        hoverOffset: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '72%',
      plugins: {
        legend: {
          display: true,
          position: 'bottom',
          labels: {
            color: '#94a3b8',
            font: { family: 'Plus Jakarta Sans', size: 11, weight: '500' },
            boxWidth: 12,
            padding: 12,
          }
        },
        tooltip: {
          backgroundColor: '#1e293b',
          titleColor: '#f8fafc',
          bodyColor: '#cbd5e1',
          borderColor: '#334155',
          borderWidth: 1,
          padding: 10,
        }
      }
    }
  });
}

function renderCategoryChart(canvasId, categoryCounts) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  if (categoryChartInstance) {
    categoryChartInstance.destroy();
  }

  const entries = Object.entries(categoryCounts || {});
  entries.sort((a, b) => b[1] - a[1]);
  const topEntries = entries.slice(0, 8);

  const labels = topEntries.map(e => e[0]);
  const data = topEntries.map(e => e[1]);

  categoryChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels.length ? labels : ['No findings'],
      datasets: [{
        label: 'Vulnerabilities',
        data: data.length ? data : [0],
        backgroundColor: 'rgba(16, 185, 129, 0.75)',
        hoverBackgroundColor: '#10b981',
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      scales: {
        x: {
          grid: { color: '#1e293b' },
          ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#cbd5e1', font: { family: 'Plus Jakarta Sans', size: 11 } }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#1e293b',
          titleColor: '#f8fafc',
          bodyColor: '#cbd5e1',
          borderColor: '#334155',
          borderWidth: 1,
        }
      }
    }
  });
}

window.charts = {
  renderSeverityChart,
  renderCategoryChart,
};
