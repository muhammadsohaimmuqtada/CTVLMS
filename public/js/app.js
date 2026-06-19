/**
 * CTVLMS — Frontend JavaScript
 * Table filtering, AJAX status updates, delete confirmations, chart init
 */

document.addEventListener('DOMContentLoaded', () => {
    initTableFilter();
    initDeleteConfirm();
    initInlineStatusUpdate();
});

/* ------------------------------------------------------------------ *
 * Client-side Table Filtering                                         *
 * ------------------------------------------------------------------ */
function initTableFilter() {
    const input = document.getElementById('tableSearch');
    if (!input) return;

    input.addEventListener('input', () => {
        const q = input.value.toLowerCase();
        const table = document.querySelector('.table-dark-custom tbody');
        if (!table) return;

        table.querySelectorAll('tr').forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(q) ? '' : 'none';
        });
    });
}

/* ------------------------------------------------------------------ *
 * Delete Confirmation                                                  *
 * ------------------------------------------------------------------ */
function initDeleteConfirm() {
    document.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', (e) => {
            if (!confirm('Are you sure you want to delete this record? This action cannot be undone.')) {
                e.preventDefault();
            }
        });
    });
}

/* ------------------------------------------------------------------ *
 * Inline Status Update (AJAX)                                         *
 * ------------------------------------------------------------------ */
function initInlineStatusUpdate() {
    document.querySelectorAll('.status-select').forEach(select => {
        select.addEventListener('change', async (e) => {
            const el   = e.target;
            const id   = el.dataset.id;
            const page = el.dataset.page;
            const csrf = el.dataset.csrf;
            const val  = el.value;

            el.disabled = true;
            el.classList.add('opacity-50');

            try {
                const form = new FormData();
                form.append('csrf_token', csrf);
                form.append('inline_status', '1');
                form.append('id', id);
                form.append('status', val);

                const resp = await fetch(`?page=${page}/form`, {
                    method: 'POST',
                    body: form
                });

                if (resp.ok) {
                    el.classList.remove('opacity-50');
                    // Brief flash effect
                    el.style.borderColor = '#00f5d4';
                    setTimeout(() => { el.style.borderColor = ''; }, 1500);
                } else {
                    alert('Failed to update status. Please refresh and try again.');
                    location.reload();
                }
            } catch (err) {
                alert('Network error. Please try again.');
                location.reload();
            } finally {
                el.disabled = false;
            }
        });
    });
}

/* ------------------------------------------------------------------ *
 * Chart.js Helpers (called from dashboard.php)                         *
 * ------------------------------------------------------------------ */

const chartColors = {
    cyan:     '#00f5d4',
    blue:     '#4361ee',
    purple:   '#7209b7',
    magenta:  '#f72585',
    orange:   '#fb8500',
    critical: '#ef4444',
    high:     '#f97316',
    medium:   '#eab308',
    low:      '#22c55e',
    grid:     'rgba(255, 255, 255, 0.05)',
    text:     '#94a3b8',
};

const defaultChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
        duration: 2500,
        easing: 'easeOutElastic'
    },
    plugins: {
        legend: {
            labels: {
                color: chartColors.text,
                font: { family: "'Inter', sans-serif", size: 12 },
                padding: 16,
            }
        }
    }
};

function createDoughnutChart(canvasId, labels, data, colors) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 0,
                hoverOffset: 8,
            }]
        },
        options: {
            ...defaultChartOptions,
            cutout: '65%',
            plugins: {
                ...defaultChartOptions.plugins,
                legend: {
                    ...defaultChartOptions.plugins.legend,
                    position: 'bottom',
                }
            }
        }
    });
}

function createBarChart(canvasId, labels, data, color) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Count',
                data: data,
                backgroundColor: color || chartColors.cyan,
                borderRadius: 6,
                borderSkipped: false,
                maxBarThickness: 50,
            }]
        },
        options: {
            ...defaultChartOptions,
            scales: {
                x: {
                    ticks: { color: chartColors.text },
                    grid: { color: chartColors.grid },
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: chartColors.text, stepSize: 1 },
                    grid: { color: chartColors.grid },
                }
            }
        }
    });
}

function createHorizontalBarChart(canvasId, labels, data, color) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Incidents',
                data: data,
                backgroundColor: color || chartColors.magenta,
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            ...defaultChartOptions,
            indexAxis: 'y',
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: { color: chartColors.text, stepSize: 1 },
                    grid: { color: chartColors.grid },
                },
                y: {
                    ticks: { color: chartColors.text },
                    grid: { display: false },
                }
            }
        }
    });
}

function createLineChart(canvasId, labels, data, color) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Incidents',
                data: data,
                borderColor: color || chartColors.cyan,
                backgroundColor: (color || chartColors.cyan) + '20',
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointHoverRadius: 8,
                pointBackgroundColor: color || chartColors.cyan,
                pointBorderWidth: 2,
                pointBorderColor: '#0a0e17',
            }]
        },
        options: {
            ...defaultChartOptions,
            scales: {
                x: {
                    ticks: { color: chartColors.text },
                    grid: { color: chartColors.grid },
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: chartColors.text, stepSize: 1 },
                    grid: { color: chartColors.grid },
                }
            }
        }
    });
}
