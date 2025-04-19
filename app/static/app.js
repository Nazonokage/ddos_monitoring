// Global variables
let connChart, trafficChart;
let updateInterval;
const MAX_HISTORY = 60;
let prevConnections = 0;

// Initialize everything when DOM loads
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    updateData();
    updateInterval = setInterval(updateData, 1000);
});

// Chart initialization with dark theme
function initializeCharts() {
    const connCtx = document.getElementById('connChart').getContext('2d');
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    
    // Chart.js global config
    Chart.defaults.color = '#a0aec0';
    Chart.defaults.borderColor = '#2d3748';

    connChart = new Chart(connCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Connections',
                data: [],
                borderColor: '#4cc9f0',
                backgroundColor: 'rgba(76, 201, 240, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.1,
                pointRadius: 0
            }]
        },
        options: getChartOptions('Connections')
    });
    
    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Traffic (KB/s)',
                data: [],
                borderColor: '#f72585',
                backgroundColor: 'rgba(247, 37, 133, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.1,
                pointRadius: 0
            }]
        },
        options: getChartOptions('Traffic (KB/s)')
    });
}

// Chart options configuration
function getChartOptions(title) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { display: false },
            tooltip: {
                mode: 'index',
                intersect: false,
                backgroundColor: '#1e293b',
                titleColor: '#f8fafc',
                bodyColor: '#e2e8f0',
                borderColor: '#334155',
                borderWidth: 1
            }
        },
        scales: {
            x: {
                grid: { color: '#334155' },
                ticks: {
                    maxRotation: 0,
                    autoSkip: true,
                    maxTicksLimit: 10
                }
            },
            y: {
                grid: { color: '#334155' },
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

// Main data update function
async function updateData() {
    try {
        const response = await fetch('/data');
        const data = await response.json();
        
        if (!data) return;
        
        // Update last update timestamp
        document.getElementById('lastUpdate').innerHTML = 
            `<i class="bi bi-clock"></i> ${new Date().toLocaleTimeString()}`;
        
        // Update all components
        updateStatus(data);
        updateSystemStats(data);
        updateTrafficAnalysis(data);
        updateAlerts(data.alerts);
        updateCharts(data.history);
        
        // Update host info
        if (data.host_info) {
            document.getElementById('host-info').textContent = 
                `${data.host_info.hostname} | ${data.host_info.os}`;
            document.getElementById('host-details').textContent = 
                `CPU: ${data.host_info.cpu_count} cores | Memory: ${data.host_info.memory_gb}GB`;
        }
        
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

// Status update with traffic direction indicators
function updateStatus(data) {
    const statusElement = document.getElementById('current-status');
    const connElement = document.getElementById('connections');
    const trafficElement = document.getElementById('traffic');
    
    if (!data.status) {
        statusElement.innerHTML = '<i class="bi bi-pause-circle"></i> Monitoring inactive';
        statusElement.className = 'alert alert-secondary mb-0 py-2';
        return;
    }
    
    // Update status with icon
    let statusClass, statusIcon;
    switch(data.status.color) {
        case 'danger': statusClass = 'danger'; statusIcon = 'bi-exclamation-triangle-fill'; break;
        case 'warning': statusClass = 'warning'; statusIcon = 'bi-exclamation-circle-fill'; break;
        case 'success': statusClass = 'success'; statusIcon = 'bi-check-circle-fill'; break;
        default: statusClass = 'secondary'; statusIcon = 'bi-pause-circle';
    }
    
    statusElement.innerHTML = `<i class="bi ${statusIcon}"></i> ${data.status.text}`;
    statusElement.className = `alert alert-${statusClass} mb-0 py-2`;
    
    // Update connections with change indicator
    const currentConnections = data.connections || 0;
    connElement.textContent = currentConnections;
    
    const connChange = document.getElementById('conn-change-indicator');
    if (currentConnections > prevConnections) {
        connChange.innerHTML = '↑';
        connChange.className = 'badge bg-danger';
    } else if (currentConnections < prevConnections) {
        connChange.innerHTML = '↓';
        connChange.className = 'badge bg-success';
    } else {
        connChange.innerHTML = '→';
        connChange.className = 'badge bg-secondary';
    }
    prevConnections = currentConnections;
    
    // Update connection progress bar
    const threshold = data.settings?.threshold || 1000;
    const connPercent = Math.min(100, (currentConnections / threshold) * 100);
    document.getElementById('conn-progress').style.width = `${connPercent}%`;
    
    // Update traffic rate
    const trafficRate = data.traffic?.rate ? data.traffic.rate.toFixed(2) : '0.00';
    trafficElement.textContent = trafficRate;
    
    // Update traffic direction indicator
    const trafficDir = document.getElementById('traffic-direction');
    const ratio = data.traffic?.direction_ratio || 0;
    if (ratio > 2) {
        trafficDir.innerHTML = '↓ IN';
        trafficDir.className = 'badge bg-danger';
    } else if (ratio < 0.5) {
        trafficDir.innerHTML = '↑ OUT';
        trafficDir.className = 'badge bg-info';
    } else {
        trafficDir.innerHTML = '⇅ BAL';
        trafficDir.className = 'badge bg-secondary';
    }
}

// System stats update
function updateSystemStats(data) {
    if (!data.system_stats) return;
    
    // CPU
    const cpu = data.system_stats.cpu || 0;
    document.getElementById('cpu').textContent = `${cpu.toFixed(1)}%`;
    document.getElementById('cpu-progress').style.width = `${cpu}%`;
    
    // Memory
    const memory = data.system_stats.memory || 0;
    document.getElementById('memory').textContent = `${memory.toFixed(1)}%`;
    document.getElementById('memory-progress').style.width = `${memory}%`;
    
    // Network
    if (data.system_stats.network) {
        document.getElementById('net-sent').textContent = (data.system_stats.network.sent / 1024).toFixed(1);
        document.getElementById('net-recv').textContent = (data.system_stats.network.recv / 1024).toFixed(1);
    }
    
    // ML Stats
    if (data.ml_stats) {
        document.getElementById('ml-score').innerHTML = 
            `<i class="bi bi-robot"></i> ML Score: ${data.ml_stats.anomaly_score.toFixed(2)}`;
    }
}

// Traffic analysis with direction indicators
function updateTrafficAnalysis(data) {
    if (!data.traffic) return;
    
    // Update source IPs table
    const sourceIps = document.getElementById('source-ips');
    if (data.traffic.top_source_ips?.length > 0) {
        sourceIps.innerHTML = data.traffic.top_source_ips.map(ip => `
            <tr class="traffic-in">
                <td class="text-truncate" style="max-width: 120px;" title="${ip[0]}">
                    <i class="bi bi-pc"></i> ${ip[0]}
                </td>
                <td class="text-end">${ip[1]} <span class="badge bg-danger">↓</span></td>
            </tr>
        `).join('');
    } else {
        sourceIps.innerHTML = '<tr><td colspan="2" class="text-center py-3">No inbound connections</td></tr>';
    }
    
    // Update top applications table
    const topApps = document.getElementById('top-apps');
    if (data.top_processes?.length > 0) {
        topApps.innerHTML = data.top_processes.map(proc => {
            const inCount = proc[1] || 0;
            const outCount = proc[2] || 0;
            let directionBadge = '⇅';
            let badgeClass = 'bg-secondary';
            
            if (inCount > outCount * 2) {
                directionBadge = '↓';
                badgeClass = 'bg-danger';
            } else if (outCount > inCount * 2) {
                directionBadge = '↑';
                badgeClass = 'bg-info';
            }
            
            return `
                <tr>
                    <td class="text-truncate" style="max-width: 150px;" title="${proc[0]}">
                        <i class="bi bi-app"></i> ${proc[0]}
                    </td>
                    <td class="text-end">
                        ${inCount + outCount} <span class="badge ${badgeClass}">${directionBadge}</span>
                    </td>
                </tr>
            `;
        }).join('');
    } else {
        topApps.innerHTML = '<tr><td colspan="2" class="text-center py-3">No process data</td></tr>';
    }
    
    // Update port activity table
    const portActivity = document.getElementById('port-activity');
    if (data.traffic.top_ports?.length > 0) {
        portActivity.innerHTML = data.traffic.top_ports.map(port => {
            const inCount = port[1] || 0;
            const outCount = port[2] || 0;
            let directionBadge = '⇅';
            let badgeClass = 'bg-secondary';
            
            if (inCount > outCount * 2) {
                directionBadge = '↓';
                badgeClass = 'bg-danger';
            } else if (outCount > inCount * 2) {
                directionBadge = '↑';
                badgeClass = 'bg-info';
            }
            
            return `
                <tr>
                    <td>
                        <span class="badge bg-dark">${port[0]}</span>
                        ${getPortService(port[0])}
                    </td>
                    <td class="text-end">
                        ${inCount + outCount} <span class="badge ${badgeClass}">${directionBadge}</span>
                    </td>
                </tr>
            `;
        }).join('');
    } else {
        portActivity.innerHTML = '<tr><td colspan="2" class="text-center py-3">No port data</td></tr>';
    }
}

// Helper function for port service names
function getPortService(port) {
    const commonPorts = {
        80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 53: 'DNS',
        3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB'
    };
    return commonPorts[port] ? `<small class="text-muted ms-2">${commonPorts[port]}</small>` : '';
}

// Alerts update
function updateAlerts(alerts) {
    const container = document.getElementById('alerts');
    
    if (!alerts || alerts.length === 0) {
        container.innerHTML = `
            <div class="alert alert-info mb-0">
                <i class="bi bi-info-circle"></i> No alerts detected
            </div>
        `;
        return;
    }
    
    container.innerHTML = alerts.map(alert => {
        let alertClass, icon;
        switch(alert.type) {
            case 'CRITICAL': alertClass = 'danger'; icon = 'bi-exclamation-triangle-fill'; break;
            case 'WARNING': alertClass = 'warning'; icon = 'bi-exclamation-circle-fill'; break;
            case 'ML CRITICAL': alertClass = 'dark'; icon = 'bi-robot'; break;
            default: alertClass = 'info'; icon = 'bi-info-circle-fill';
        }
        
        return `
            <div class="alert alert-${alertClass} alert-dismissible fade show mb-2">
                <i class="bi ${icon}"></i> <strong>${alert.type}</strong>: ${alert.message}
                <small class="text-muted float-end">${alert.timestamp}</small>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
    }).join('');
}

// Charts update
function updateCharts(history) {
    if (!history) return;
    
    // Update connections chart
    if (history.connections && history.labels) {
        connChart.data.labels = history.labels;
        connChart.data.datasets[0].data = history.connections;
        const avg = history.connections.reduce((a, b) => a + b, 0) / history.connections.length;
        document.getElementById('conn-stats').textContent = `Avg: ${avg.toFixed(1)}`;
        connChart.update();
    }
    
    // Update traffic chart
    if (history.traffic && history.labels) {
        trafficChart.data.labels = history.labels;
        trafficChart.data.datasets[0].data = history.traffic;
        const avg = history.traffic.reduce((a, b) => a + b, 0) / history.traffic.length;
        document.getElementById('traffic-stats').textContent = `Avg: ${avg.toFixed(1)} KB/s`;
        trafficChart.update();
    }
}

// Control functions
async function startMonitoring() {
    try {
        document.getElementById('startBtn').disabled = true;
        document.getElementById('stopBtn').disabled = false;
        
        const response = await fetch('/start');
        const result = await response.json();
        
        if (result.status === 'Monitoring started') {
            updateData();
            document.getElementById('current-status').classList.add('animate__animated', 'animate__pulse');
        }
    } catch (error) {
        console.error('Error starting monitoring:', error);
    }
}

async function stopMonitoring() {
    try {
        document.getElementById('stopBtn').disabled = true;
        
        const response = await fetch('/stop');
        const result = await response.json();
        
        if (result.status === 'Monitoring stopped') {
            document.getElementById('current-status').innerHTML = 
                '<i class="bi bi-pause-circle"></i> Monitoring stopped';
            document.getElementById('current-status').className = 'alert alert-secondary mb-0 py-2';
            document.getElementById('current-status').classList.remove('animate__animated', 'animate__pulse');
        }
    } catch (error) {
        console.error('Error stopping monitoring:', error);
    } finally {
        document.getElementById('stopBtn').disabled = false;
        document.getElementById('startBtn').disabled = false;
    }
}

// Settings functions
function saveSettings() {
    const threshold = document.getElementById('thresholdInput').value;
    const alertThreshold = document.getElementById('alertThresholdInput').value;
    const interval = document.getElementById('intervalInput').value;
    
    fetch('/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threshold, alertThreshold, interval })
    }).then(response => {
        if (response.ok) {
            document.getElementById('threshold-value').textContent = threshold;
            clearInterval(updateInterval);
            updateInterval = setInterval(updateData, interval);
            
            const toast = new bootstrap.Toast(document.getElementById('settingsToast'));
            toast.show();
            
            bootstrap.Modal.getInstance(document.getElementById('settingsModal')).hide();
        }
    });
}

// Handle page visibility changes
document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        clearInterval(updateInterval);
    } else {
        updateData();
        updateInterval = setInterval(updateData, 1000);
    }
});