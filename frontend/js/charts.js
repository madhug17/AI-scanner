/**
 * AI App Security & Quality Scanner — Charts Controller
 * Premium Minimalist Palette (No neon, muted enterprise tones)
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

  // Muted, professional enterprise colors
  const palette = ['#f85149', '#f0883e', '#d29922', '#58a6ff', '#8b949e'];

  severityChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: total === 0 ? [1] : data,
        backgroundColor: total === 0 ? ['#21262d'] : palette,
        borderWidth: 2,
        borderColor: '#161b22',
        hoverOffset: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '74%',
      plugins: {
        legend: {
          display: true,
          position: 'bottom',
          labels: {
            color: '#8b949e',
            font: { family: 'Plus Jakarta Sans', size: 11, weight: '500' },
            boxWidth: 10,
            padding: 12,
          }
        },
        tooltip: {
          backgroundColor: '#21262d',
          titleColor: '#f0f6fc',
          bodyColor: '#c9d1d9',
          borderColor: '#30363d',
          borderWidth: 1,
          padding: 8,
          boxPadding: 4,
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
        label: 'Findings',
        data: data.length ? data : [0],
        backgroundColor: '#30363d',
        hoverBackgroundColor: '#58a6ff',
        borderRadius: 3,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      scales: {
        x: {
          grid: { color: '#21262d' },
          ticks: { color: '#8b949e', font: { family: 'JetBrains Mono', size: 10 } }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#c9d1d9', font: { family: 'Plus Jakarta Sans', size: 11 } }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#21262d',
          titleColor: '#f0f6fc',
          bodyColor: '#c9d1d9',
          borderColor: '#30363d',
          borderWidth: 1,
          padding: 8,
        }
      }
    }
  });
}

window.charts = {
  renderSeverityChart,
  renderCategoryChart,
};
