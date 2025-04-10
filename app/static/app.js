// Global chart references
let connChart, trafficChart;
let updateInterval;
const MAX_HISTORY = 60; // Keep 60 data points

// Initialize charts when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    updateData(); // Initial data load
    
    // Set up periodic updates
    updateInterval = setInterval(updateData, 1000);
});

function initializeCharts() {
    const connCtx = document.getElementById('connChart').getContext('2d');
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    
    connChart = new Chart(connCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Connections',
                data: [],
                borderColor: 'rgba(54, 162, 235, 1)',
                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.1
            }]
        },
        options: getChartOptions('Connections')
    });
    
    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Traffic (KB)',
                data: [],
                borderColor: 'rgba(75, 192, 192, 1)',
                backgroundColor: 'rgba(75, 192, 192, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.1
            }]
        },
        options: getChartOptions('Traffic (KB)')
    });
}

function getChartOptions(title) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: false
            },
            title: {
                display: false
            },
            tooltip: {
                mode: 'index',
                intersect: false
            }
        },
        scales: {
            x: {
                grid: {
                    display: false
                },
                ticks: {
                    maxRotation: 0,
                    autoSkip: true,
                    maxTicksLimit: 10
                }
            },
            y: {
                beginAtZero: true,
                grace: '5%'
            }
        },
        interaction: {
            mode: 'nearest',
            axis: 'x',
            intersect: false
        }
    };
}

async function updateData() {
    try {
        const response = await fetch('/data');
        const data = await response.json();
        
        if (!data) return;
        
        // Update last update timestamp
        document.getElementById('lastUpdate').textContent = `Last update: ${new Date().toLocaleTimeString()}`;
        
        // Update status
        updateStatus(data);
        
        // Update system stats
        updateSystemStats(data.system_stats);
        
        // Update process list
        updateProcessList(data.top_processes);
        
        // Update alerts
        updateAlerts(data.alerts);
        
        // Update charts
        updateCharts(data.history);
        
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

function updateStatus(data) {
    const statusElement = document.getElementById('current-status');
    
    if (!data.status) {
        statusElement.innerHTML = '<span class="badge bg-secondary">Not monitoring</span>';
        return;
    }
    
    let badgeClass;
    switch(data.status.color) {
        case 'danger': badgeClass = 'bg-danger'; break;
        case 'warning': badgeClass = 'bg-warning'; break;
        case 'success': badgeClass = 'bg-success'; break;
        default: badgeClass = 'bg-secondary';
    }
    
    statusElement.innerHTML = `<span class="badge ${badgeClass}">${data.status.text}</span>`;
    
    // Update connections and traffic
    document.getElementById('connections').textContent = data.connections || '0';
    document.getElementById('traffic').textContent = data.traffic_rate ? data.traffic_rate.toFixed(2) : '0.00';
}

function updateSystemStats(stats) {
    if (!stats) return;
    
    document.getElementById('cpu').textContent = stats.cpu ? stats.cpu.toFixed(1) : '0';
    document.getElementById('memory').textContent = stats.memory ? stats.memory.toFixed(1) : '0';
    
    if (stats.network) {
        document.getElementById('net-sent').textContent = (stats.network.sent / 1024).toFixed(1);
        document.getElementById('net-recv').textContent = (stats.network.recv / 1024).toFixed(1);
    }
}

function updateProcessList(processes) {
    const tbody = document.getElementById('processes');
    
    if (!processes || processes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="2" class="text-center text-muted">No processes found</td></tr>';
        return;
    }
    
    let html = '';
    processes.forEach(proc => {
        html += `
            <tr>
                <td class="text-truncate" style="max-width: 200px;" title="${proc[0]}">${proc[0]}</td>
                <td class="text-end">${proc[1]}</td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

function updateAlerts(alerts) {
    const container = document.getElementById('alerts');
    
    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div class="alert alert-info">No alerts yet</div>';
        return;
    }
    
    let html = '';
    alerts.forEach(alert => {
        let alertClass;
        switch(alert.type) {
            case 'CRITICAL': alertClass = 'danger'; break;
            case 'WARNING': alertClass = 'warning'; break;
            default: alertClass = 'info';
        }
        
        html += `
            <div class="alert alert-${alertClass} alert-dismissible fade show">
                <strong>${alert.type}</strong>: ${alert.message}
                <small class="text-muted float-end">${alert.timestamp}</small>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function updateCharts(history) {
    if (!history) return;
    
    // Update connections chart
    if (history.connections && history.labels) {
        connChart.data.labels = history.labels;
        connChart.data.datasets[0].data = history.connections;
        connChart.update();
    }
    
    // Update traffic chart
    if (history.traffic && history.labels) {
        trafficChart.data.labels = history.labels;
        trafficChart.data.datasets[0].data = history.traffic;
        trafficChart.update();
    }
}

async function startMonitoring() {
    try {
        document.getElementById('startBtn').disabled = true;
        document.getElementById('stopBtn').disabled = false;
        
        const response = await fetch('/start');
        const result = await response.json();
        
        if (result.status === 'Monitoring started') {
            // Update immediately after starting
            updateData();
        }
    } catch (error) {
        console.error('Error starting monitoring:', error);
    } finally {
        document.getElementById('startBtn').disabled = false;
    }
}

async function stopMonitoring() {
    try {
        document.getElementById('stopBtn').disabled = true;
        
        const response = await fetch('/stop');
        const result = await response.json();
        
        if (result.status === 'Monitoring stopped') {
            // Update status immediately
            document.getElementById('current-status').innerHTML = 
                '<span class="badge bg-secondary">Monitoring stopped</span>';
        }
    } catch (error) {
        console.error('Error stopping monitoring:', error);
    } finally {
        document.getElementById('stopBtn').disabled = false;
        document.getElementById('startBtn').disabled = false;
    }
}

// Handle page visibility changes to save resources
document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        clearInterval(updateInterval);
    } else {
        updateInterval = setInterval(updateData, 1000);
        updateData(); // Immediate update when returning to tab
    }
});