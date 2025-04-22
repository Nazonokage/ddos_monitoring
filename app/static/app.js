// Global chart references
let connChart, trafficChart;
let updateInterval;
const MAX_HISTORY = 60; // Keep 60 data points
let previousConnections = 0;
let previousTraffic = 0;

// Initialize charts when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    initializeProgressBars();
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

function initializeProgressBars() {
    // Initialize all progress bars to 0%
    document.getElementById('conn-progress').style.width = '0%';
    document.getElementById('cpu-progress').style.width = '0%';
    document.getElementById('memory-progress').style.width = '0%';
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
        const now = new Date();
        document.getElementById('lastUpdate').innerHTML = `<i class="bi bi-clock"></i> ${now.toLocaleTimeString()}`;
        
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
        
        // Update progress bars and indicators
        updateProgressBars(data);
        
        // Store current values for next comparison
        if (data.connections) previousConnections = data.connections;
        if (data.traffic_rate) previousTraffic = data.traffic_rate;
        
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

function updateStatus(data) {
    const statusElement = document.getElementById('current-status');
    
    if (!data.status) {
        statusElement.innerHTML = '<i class="bi bi-pause-circle"></i> Monitoring inactive';
        statusElement.className = 'alert alert-secondary mb-0 py-2';
        return;
    }
    
    let alertClass, iconClass;
    switch(data.status.color) {
        case 'danger': 
            alertClass = 'alert-danger';
            iconClass = 'bi-exclamation-triangle';
            break;
        case 'warning': 
            alertClass = 'alert-warning';
            iconClass = 'bi-exclamation-circle';
            break;
        case 'success': 
            alertClass = 'alert-success';
            iconClass = 'bi-check-circle';
            break;
        default: 
            alertClass = 'alert-secondary';
            iconClass = 'bi-pause-circle';
    }
    
    statusElement.innerHTML = `<i class="bi ${iconClass}"></i> ${data.status.text}`;
    statusElement.className = `alert ${alertClass} mb-0 py-2`;
    
    // Update connections and traffic
    const connections = data.connections || 0;
    const traffic = data.traffic_rate ? data.traffic_rate.toFixed(2) : '0.00';
    
    document.getElementById('connections').textContent = connections;
    document.getElementById('traffic').textContent = traffic;
    
    // Update direction indicators
    updateDirectionIndicators(connections, traffic);
}

function updateDirectionIndicators(connections, traffic) {
    const connIndicator = document.getElementById('conn-change-indicator');
    const trafficIndicator = document.getElementById('traffic-direction');
    
    // Connection direction indicator
    if (connections > previousConnections) {
        connIndicator.textContent = '↑';
        connIndicator.className = 'badge bg-danger direction';
    } else if (connections < previousConnections) {
        connIndicator.textContent = '↓';
        connIndicator.className = 'badge bg-success direction';
    } else {
        connIndicator.textContent = '→';
        connIndicator.className = 'badge bg-primary direction';
    }
    
    // Traffic direction indicator
    const trafficNum = parseFloat(traffic);
    if (trafficNum > previousTraffic) {
        trafficIndicator.textContent = '↑↑';
        trafficIndicator.className = 'badge bg-danger direction';
    } else if (trafficNum < previousTraffic) {
        trafficIndicator.textContent = '↓↓';
        trafficIndicator.className = 'badge bg-success direction';
    } else {
        trafficIndicator.textContent = '⇅';
        trafficIndicator.className = 'badge bg-info direction';
    }
}

function updateSystemStats(stats) {
    if (!stats) return;
    
    const cpu = stats.cpu ? stats.cpu.toFixed(1) : '0';
    const memory = stats.memory ? stats.memory.toFixed(1) : '0';
    
    document.getElementById('cpu').textContent = `${cpu}%`;
    document.getElementById('memory').textContent = `${memory}%`;
    
    // Update progress bars
    document.getElementById('cpu-progress').style.width = `${cpu}%`;
    document.getElementById('memory-progress').style.width = `${memory}%`;
    
    if (stats.network) {
        const sent = (stats.network.sent / 1024).toFixed(1);
        const recv = (stats.network.recv / 1024).toFixed(1);
        
        document.getElementById('net-sent').textContent = sent;
        document.getElementById('net-recv').textContent = recv;
        
        // Update footer stats
        document.getElementById('cpu-footer').textContent = cpu;
        document.getElementById('memory-footer').textContent = memory;
        document.getElementById('net-sent-footer').textContent = sent;
        document.getElementById('net-recv-footer').textContent = recv;
    }
}

function updateProgressBars(data) {
    const threshold = parseInt(document.getElementById('threshold-value').textContent) || 1000;
    const connections = data.connections || 0;
    
    // Connection progress bar (percentage of threshold)
    const connPercentage = Math.min(100, (connections / threshold) * 100);
    const connProgress = document.getElementById('conn-progress');
    connProgress.style.width = `${connPercentage}%`;
    
    // Change color based on threshold
    if (connPercentage >= 90) {
        connProgress.className = 'progress-bar bg-danger';
    } else if (connPercentage >= 70) {
        connProgress.className = 'progress-bar bg-warning';
    } else {
        connProgress.className = 'progress-bar bg-primary';
    }
    
    // Update connection stats badge
    const avgConnections = data.history?.connections ? 
        (data.history.connections.reduce((a, b) => a + b, 0) / data.history.connections.length).toFixed(1) : 0;
    document.getElementById('conn-stats').textContent = `Avg: ${avgConnections}`;
    
    // Update traffic stats badge
    const avgTraffic = data.history?.traffic ? 
        (data.history.traffic.reduce((a, b) => a + b, 0) / data.history.traffic.length).toFixed(1) : 0;
    document.getElementById('traffic-stats').textContent = `Avg: ${avgTraffic} KB/s`;
}

function updateProcessList(processes) {
    const tbody = document.getElementById('processes');
    
    if (!processes || processes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="2" class="text-center py-3">No data available</td></tr>';
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
        container.innerHTML = '<div class="alert alert-info mb-0"><i class="bi bi-info-circle"></i> No alerts detected</div>';
        return;
    }
    
    let html = '';
    alerts.forEach(alert => {
        let alertClass, iconClass;
        switch(alert.type) {
            case 'CRITICAL': 
                alertClass = 'danger';
                iconClass = 'bi-exclamation-triangle-fill';
                break;
            case 'WARNING': 
                alertClass = 'warning';
                iconClass = 'bi-exclamation-triangle';
                break;
            default: 
                alertClass = 'info';
                iconClass = 'bi-info-circle';
        }
        
        html += `
            <div class="alert alert-${alertClass} alert-dismissible fade show mb-2">
                <i class="bi ${iconClass}"></i> 
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
        showAlert('Error starting monitoring', 'danger');
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
                '<i class="bi bi-pause-circle"></i> Monitoring stopped';
            document.getElementById('current-status').className = 'alert alert-secondary mb-0 py-2';
        }
    } catch (error) {
        console.error('Error stopping monitoring:', error);
        showAlert('Error stopping monitoring', 'danger');
    } finally {
        document.getElementById('stopBtn').disabled = false;
        document.getElementById('startBtn').disabled = false;
    }
}

function showAlert(message, type) {
    const alertsContainer = document.getElementById('alerts');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show mb-2`;
    alert.innerHTML = `
        <i class="bi ${type === 'danger' ? 'bi-exclamation-triangle-fill' : 'bi-info-circle-fill'}"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    alertsContainer.prepend(alert);
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

// Settings functions
async function saveSettings() {
    try {
        const threshold = document.getElementById('thresholdInput').value;
        const interval = document.getElementById('intervalInput').value;
        
        const response = await fetch('/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                threshold: parseInt(threshold),
                interval: parseInt(interval)
            })
        });
        
        const result = await response.json();
        if (result.success) {
            // Update displayed threshold
            document.getElementById('threshold-value').textContent = threshold;
            
            // Update interval if changed
            if (interval !== updateInterval._idleTimeout) {
                clearInterval(updateInterval);
                updateInterval = setInterval(updateData, interval);
            }
            
            // Close modal
            bootstrap.Modal.getInstance(document.getElementById('settingsModal')).hide();
            
            showAlert('Settings saved successfully', 'success');
        }
    } catch (error) {
        console.error('Error saving settings:', error);
        showAlert('Error saving settings', 'danger');
    }
}