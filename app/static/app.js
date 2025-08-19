// Enhanced DDoS Monitor Dashboard with Advanced Alert System
class EnhancedDDoSMonitor {
    constructor() {
        this.connChart = null;
        this.trafficChart = null;
        this.packetChart = null;
        this.updateInterval = null;
        this.MAX_HISTORY = 60;
        this.previousConnections = 0;
        this.previousTraffic = 0;
        this.previousPackets = 0;
        this.currentEndpoints = [];
        this.suspiciousEndpoints = [];
        this.updateIntervalMs = 1000;
        this.alertSound = null;
        this.lastAlertCount = 0;
        this.audioContext = null;
        
        this.init();
    }

    init() {
        document.addEventListener('DOMContentLoaded', () => {
            this.initializeCharts();
            this.initializeProgressBars();
            this.initializeAlertSystem();
            this.updateData();
            this.setupEventListeners();
            
            this.updateInterval = setInterval(() => this.updateData(), this.updateIntervalMs);
        });
    }

    initializeAlertSystem() {
        try {
            this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
        } catch (e) {
            console.log('Audio alerts not supported in this browser');
        }
        
        // Request notification permission
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    playAlertSound(type = 'warning') {
        if (!this.audioContext) return;
        
        try {
            const oscillator = this.audioContext.createOscillator();
            const gainNode = this.audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(this.audioContext.destination);
            
            const frequencies = {
                'critical': [800, 600, 800],
                'warning': [400, 500],
                'info': [300]
            };
            
            const freq = frequencies[type] || frequencies['warning'];
            oscillator.frequency.setValueAtTime(freq[0], this.audioContext.currentTime);
            
            gainNode.gain.setValueAtTime(0.1, this.audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + 0.5);
            
            oscillator.start(this.audioContext.currentTime);
            oscillator.stop(this.audioContext.currentTime + 0.5);
        } catch (e) {
            console.log('Error playing alert sound:', e);
        }
    }

    setupEventListeners() {
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                clearInterval(this.updateInterval);
            } else {
                this.updateInterval = setInterval(() => this.updateData(), this.updateIntervalMs);
                this.updateData();
            }
        });

        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case 's':
                        e.preventDefault();
                        this.startMonitoring();
                        break;
                    case 'x':
                        e.preventDefault();
                        this.stopMonitoring();
                        break;
                    case 'r':
                        e.preventDefault();
                        this.generateReport();
                        break;
                }
            }
        });
    }

    initializeCharts() {
        const commonOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                annotation: {
                    annotations: {}
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        maxRotation: 0,
                        autoSkip: true,
                        maxTicksLimit: 10
                    }
                },
                y: { 
                    beginAtZero: true, 
                    grace: '5%',
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            }
        };

        // Connections Chart
        this.connChart = new Chart(
            document.getElementById('connChart').getContext('2d'),
            {
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
                options: {
                    ...commonOptions,
                    plugins: {
                        ...commonOptions.plugins,
                        title: {
                            display: true,
                            text: 'Active Connections Over Time'
                        }
                    }
                }
            }
        );

        // Traffic Chart
        this.trafficChart = new Chart(
            document.getElementById('trafficChart').getContext('2d'),
            {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Traffic (KB/s)',
                        data: [],
                        borderColor: 'rgba(75, 192, 192, 1)',
                        backgroundColor: 'rgba(75, 192, 192, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.1
                    }]
                },
                options: {
                    ...commonOptions,
                    plugins: {
                        ...commonOptions.plugins,
                        title: {
                            display: true,
                            text: 'Network Traffic Over Time'
                        }
                    }
                }
            }
        );

        // Packet Chart (if element exists)
        const packetChartElement = document.getElementById('packetChart');
        if (packetChartElement) {
            this.packetChart = new Chart(
                packetChartElement.getContext('2d'),
                {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Packets/s',
                            data: [],
                            borderColor: 'rgba(255, 99, 132, 1)',
                            backgroundColor: 'rgba(255, 99, 132, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.1
                        }]
                    },
                    options: {
                        ...commonOptions,
                        plugins: {
                            ...commonOptions.plugins,
                            title: {
                                display: true,
                                text: 'Packet Rate Over Time'
                            }
                        }
                    }
                }
            );
        }
    }

    initializeProgressBars() {
        ['conn', 'cpu', 'memory'].forEach(id => {
            const progressBar = document.getElementById(`${id}-progress`);
            if (progressBar) {
                progressBar.style.width = '0%';
            }
        });
    }

    async updateData() {
        try {
            const response = await fetch('/data');
            const data = await response.json();
            
            if (!data) return;
            
            this.updateLastUpdateTime();
            this.updateStatus(data);
            this.updateSystemStats(data.system_stats);
            this.updateProcessList(data.top_processes);
            this.updateEndpointsList(data.top_endpoints);
            this.updateSuspiciousEndpoints(data.suspicious_endpoints);
            this.updateAlerts(data.alerts);
            this.updateAttackSummary(data.attack_summary);
            this.updateCharts(data.history);
            this.updateProgressBars(data);
            this.updateBaselineInfo(data.baseline_info);
            
            this.checkForNewAlerts(data.alerts);
            
            if (data.connections !== undefined) this.previousConnections = data.connections;
            if (data.traffic_rate !== undefined) this.previousTraffic = data.traffic_rate;
            if (data.packet_rate !== undefined) this.previousPackets = data.packet_rate;
            
        } catch (error) {
            console.error('Error fetching data:', error);
            this.showAlert('Connection error: Unable to fetch monitoring data', 'danger');
        }
    }

    checkForNewAlerts(alerts) {
        if (!alerts) return;
        
        const newAlertCount = alerts.length;
        if (newAlertCount > this.lastAlertCount) {
            const newAlerts = alerts.slice(this.lastAlertCount);
            
            const hasCritical = newAlerts.some(alert => alert.type === 'CRITICAL');
            if (hasCritical) {
                this.playAlertSound('critical');
            } else {
                this.playAlertSound('warning');
            }
            
            this.showBrowserNotification(newAlerts);
        }
        this.lastAlertCount = newAlertCount;
    }

    showBrowserNotification(alerts) {
        if (Notification.permission === 'granted' && alerts.length > 0) {
            const alert = alerts[alerts.length - 1];
            new Notification('DDoS Monitor Alert', {
                body: alert.message,
                icon: '/static/favicon.ico',
                tag: 'ddos-alert'
            });
        }
    }

    updateLastUpdateTime() {
        const now = new Date();
        document.getElementById('lastUpdate').innerHTML = 
            `<i class="bi bi-clock"></i> ${now.toLocaleTimeString()}`;
    }

    updateStatus(data) {
        const statusElement = document.getElementById('current-status');
        
        if (!data.status) {
            statusElement.innerHTML = '<i class="bi bi-pause-circle"></i> Monitoring inactive';
            statusElement.className = 'alert alert-secondary mb-0 py-2';
            return;
        }
        
        const statusClasses = {
            danger: { alert: 'alert-danger', icon: 'bi-exclamation-triangle' },
            warning: { alert: 'alert-warning', icon: 'bi-exclamation-circle' },
            success: { alert: 'alert-success', icon: 'bi-check-circle' },
            default: { alert: 'alert-secondary', icon: 'bi-pause-circle' }
        };
        
        const status = statusClasses[data.status.color] || statusClasses.default;
        
        statusElement.innerHTML = `<i class="bi ${status.icon}"></i> ${data.status.text}`;
        statusElement.className = `alert ${status.alert} mb-0 py-2`;
        
        const connections = data.connections || 0;
        const traffic = data.traffic_rate ? data.traffic_rate.toFixed(2) : '0.00';
        
        document.getElementById('connections').textContent = connections;
        document.getElementById('traffic').textContent = traffic;
        
        this.updateDirectionIndicators(connections, traffic);
    }

    updateDirectionIndicators(connections, traffic) {
        const connIndicator = document.getElementById('conn-change-indicator');
        const trafficIndicator = document.getElementById('traffic-direction');
        
        if (connections > this.previousConnections) {
            connIndicator.textContent = '↑';
            connIndicator.className = 'badge bg-danger direction';
        } else if (connections < this.previousConnections) {
            connIndicator.textContent = '↓';
            connIndicator.className = 'badge bg-success direction';
        } else {
            connIndicator.textContent = '→';
            connIndicator.className = 'badge bg-primary direction';
        }
        
        const trafficNum = parseFloat(traffic);
        if (trafficNum > this.previousTraffic) {
            trafficIndicator.textContent = '↑↑';
            trafficIndicator.className = 'badge bg-danger direction';
        } else if (trafficNum < this.previousTraffic) {
            trafficIndicator.textContent = '↓↓';
            trafficIndicator.className = 'badge bg-success direction';
        } else {
            trafficIndicator.textContent = '⇅';
            trafficIndicator.className = 'badge bg-info direction';
        }
    }

    updateSystemStats(stats) {
        if (!stats) return;
        
        const cpu = stats.cpu ? stats.cpu.toFixed(1) : '0';
        const memory = stats.memory ? stats.memory.toFixed(1) : '0';
        
        document.getElementById('cpu').textContent = `${cpu}%`;
        document.getElementById('memory').textContent = `${memory}%`;
        
        document.getElementById('cpu-progress').style.width = `${cpu}%`;
        document.getElementById('memory-progress').style.width = `${memory}%`;
        
        if (stats.network) {
            const sent = (stats.network.sent / 1024).toFixed(1);
            const recv = (stats.network.recv / 1024).toFixed(1);
            
            document.getElementById('net-sent').textContent = sent;
            document.getElementById('net-recv').textContent = recv;
            
            document.getElementById('cpu-footer').textContent = cpu;
            document.getElementById('memory-footer').textContent = memory;
            document.getElementById('net-sent-footer').textContent = sent;
            document.getElementById('net-recv-footer').textContent = recv;
        }
    }

    updateProgressBars(data) {
        const threshold = parseInt(document.getElementById('threshold-value').textContent) || 1000;
        const connections = data.connections || 0;
        const connPercentage = Math.min(100, (connections / threshold) * 100);
        const connProgress = document.getElementById('conn-progress');
        
        connProgress.style.width = `${connPercentage}%`;
        
        if (connPercentage >= 90) {
            connProgress.className = 'progress-bar bg-danger';
        } else if (connPercentage >= 70) {
            connProgress.className = 'progress-bar bg-warning';
        } else {
            connProgress.className = 'progress-bar bg-primary';
        }
        
        if (data.history?.connections) {
            const avgConn = (data.history.connections.reduce((a, b) => a + b, 0) / data.history.connections.length).toFixed(1);
            const maxConn = Math.max(...data.history.connections).toFixed(1);
            document.getElementById('conn-stats').textContent = `Avg: ${avgConn} | Max: ${maxConn}`;
        }
        
        if (data.history?.traffic) {
            const avgTraffic = (data.history.traffic.reduce((a, b) => a + b, 0) / data.history.traffic.length).toFixed(1);
            const maxTraffic = Math.max(...data.history.traffic).toFixed(1);
            document.getElementById('traffic-stats').textContent = `Avg: ${avgTraffic} KB/s | Max: ${maxTraffic} KB/s`;
        }
    }

    updateProcessList(processes) {
        const tbody = document.getElementById('processes');
        
        if (!processes || !processes.length) {
            tbody.innerHTML = '<tr><td colspan="2" class="text-center py-3">No data available</td></tr>';
            return;
        }
        
        tbody.innerHTML = processes.map(proc => `
            <tr>
                <td class="text-truncate" style="max-width: 200px;" title="${proc[0]}">${proc[0]}</td>
                <td class="text-end">${proc[1]}</td>
            </tr>
        `).join('');
    }

    updateEndpointsList(endpoints) {
        const tbody = document.getElementById('endpoints');
        
        if (!endpoints || !endpoints.length) {
            tbody.innerHTML = '<tr><td colspan="2" class="text-center py-3">No data available</td></tr>';
            this.currentEndpoints = [];
            return;
        }
        
        this.currentEndpoints = endpoints;
        tbody.innerHTML = endpoints.map(([endpoint, data]) => `
            <tr onclick="ddosMonitor.showEndpointDetails('${endpoint}')" style="cursor: pointer;">
                <td class="text-truncate" style="max-width: 200px;" title="${endpoint}">
                    ${endpoint.split(':')[0]}
                    <small class="text-muted">:${endpoint.split(':')[1]}</small>
                </td>
                <td class="text-end">${data.count}</td>
            </tr>
        `).join('');
    }

    updateSuspiciousEndpoints(suspicious) {
        const container = document.getElementById('suspicious-endpoints');
        if (!container) return;
        
        this.suspiciousEndpoints = suspicious || [];
        
        if (!suspicious || suspicious.length === 0) {
            container.innerHTML = '<div class="alert alert-success mb-0"><i class="bi bi-shield-check"></i> No suspicious activity detected</div>';
            return;
        }
        
        container.innerHTML = suspicious.map(endpoint => {
            const riskLevel = endpoint.score > 50 ? 'danger' : endpoint.score > 20 ? 'warning' : 'info';
            const riskText = endpoint.score > 50 ? 'HIGH' : endpoint.score > 20 ? 'MEDIUM' : 'LOW';
            
            return `
                <div class="alert alert-${riskLevel} mb-2">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <strong>${endpoint.ip}</strong> 
                            <span class="badge bg-${riskLevel}">${riskText} RISK</span>
                            <br>
                            <small>
                                ${endpoint.connections} connections | 
                                ${endpoint.ports_targeted} ports | 
                                Score: ${endpoint.score}
                            </small>
                        </div>
                        <button class="btn btn-sm btn-outline-${riskLevel}" 
                                onclick="ddosMonitor.showSuspiciousDetails('${endpoint.ip}')">
                            Details
                        </button>
                    </div>
                    ${endpoint.flags.length > 0 ? `
                        <div class="mt-2">
                            <strong>Flags:</strong> ${endpoint.flags.join(', ')}
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');
    }

    updateAttackSummary(attackSummary) {
        const container = document.getElementById('attack-summary');
        if (!container || !attackSummary) return;
        
        const detectedAttacks = Object.entries(attackSummary).filter(([_, data]) => data.detected);
        
        if (detectedAttacks.length === 0) {
            container.innerHTML = '<div class="alert alert-success mb-0"><i class="bi bi-shield-check"></i> No active attacks detected</div>';
            return;
        }
        
        container.innerHTML = detectedAttacks.map(([pattern, data]) => `
            <div class="alert alert-danger mb-2">
                <div class="d-flex justify-content-between">
                    <div>
                        <strong>${pattern.replace('_', ' ').toUpperCase()}</strong>
                        <br>
                        <small>Incidents: ${data.count} | Last seen: ${data.last_seen}</small>
                    </div>
                    <i class="bi bi-exclamation-triangle-fill text-danger"></i>
                </div>
            </div>
        `).join('');
    }

    updateBaselineInfo(baselineInfo) {
        if (!baselineInfo) return;
        
        const baselineElement = document.getElementById('baseline-info');
        if (baselineElement && baselineInfo.established) {
            baselineElement.innerHTML = `
                <div class="small text-muted">
                    <strong>Baseline:</strong> 
                    ${baselineInfo.connections.toFixed(1)} conn/s | 
                    ${baselineInfo.traffic.toFixed(1)} KB/s | 
                    ${baselineInfo.packets.toFixed(0)} pkt/s
                </div>
            `;
        }
    }

    updateAlerts(alerts) {
        const container = document.getElementById('alerts');
        
        if (!alerts || alerts.length === 0) {
            container.innerHTML = '<div class="alert alert-info mb-0"><i class="bi bi-info-circle"></i> No alerts detected</div>';
            return;
        }
        
        const sortedAlerts = [...alerts].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        const recentAlerts = sortedAlerts.slice(0, 5);
        
        const alertTypes = {
            CRITICAL: { class: 'danger', icon: 'bi-exclamation-triangle-fill' },
            WARNING: { class: 'warning', icon: 'bi-exclamation-triangle' },
            INFO: { class: 'info', icon: 'bi-info-circle' }
        };
        
        container.innerHTML = recentAlerts.map(alert => {
            const type = alertTypes[alert.type] || alertTypes.INFO;
            const hasDetails = alert.details && Object.keys(alert.details).length > 0;
            
            return `
                <div class="alert alert-${type.class} alert-dismissible fade show mb-2" 
                     ${hasDetails ? `onclick="ddosMonitor.showAlertDetails('${alert.timestamp}')"` : ''} 
                     ${hasDetails ? 'style="cursor: pointer;"' : ''}>
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <i class="bi ${type.icon}"></i> 
                            <strong>${alert.type}</strong>
                            ${alert.category ? `<span class="badge bg-secondary ms-2">${alert.category}</span>` : ''}
                            <br>
                            <span class="alert-message">${alert.message}</span>
                        </div>
                        <div class="text-end">
                            <small class="text-muted">${new Date(alert.timestamp).toLocaleTimeString()}</small>
                            ${alert.severity ? `<br><span class="badge bg-${alert.severity === 'HIGH' ? 'danger' : alert.severity === 'MEDIUM' ? 'warning' : 'info'}">${alert.severity}</span>` : ''}
                        </div>
                    </div>
                    ${hasDetails ? '<small class="text-muted"><i class="bi bi-info-circle"></i> Click for details</small>' : ''}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            `;
        }).join('');
    }

    updateCharts(history) {
        if (!history) return;
        
        if (history.connections && history.labels) {
            const maxConnections = Math.max(...history.connections);
            
            this.connChart.data.labels = history.labels;
            this.connChart.data.datasets[0].data = history.connections;
            this.connChart.options.plugins.annotation.annotations.maxLine = {
                type: 'line',
                yMin: maxConnections,
                yMax: maxConnections,
                borderColor: 'rgba(255, 99, 132, 0.5)',
                borderWidth: 1,
                borderDash: [6, 6],
                label: {
                    content: `Max: ${maxConnections.toFixed(1)}`,
                    enabled: true,
                    position: 'right'
                }
            };
            this.connChart.update();
        }
        
        if (history.traffic && history.labels) {
            const maxTraffic = Math.max(...history.traffic);
            
            this.trafficChart.data.labels = history.labels;
            this.trafficChart.data.datasets[0].data = history.traffic;
            this.trafficChart.options.plugins.annotation.annotations.maxLine = {
                type: 'line',
                yMin: maxTraffic,
                yMax: maxTraffic,
                borderColor: 'rgba(255, 99, 132, 0.5)',
                borderWidth: 1,
                borderDash: [6, 6],
                label: {
                    content: `Max: ${maxTraffic.toFixed(1)} KB/s`,
                    enabled: true,
                    position: 'right'
                }
            };
            this.trafficChart.update();
        }
        
        if (this.packetChart && history.packets && history.labels) {
            const maxPackets = Math.max(...history.packets);
            
            this.packetChart.data.labels = history.labels;
            this.packetChart.data.datasets[0].data = history.packets;
            this.packetChart.options.plugins.annotation.annotations.maxLine = {
                type: 'line',
                yMin: maxPackets,
                yMax: maxPackets,
                borderColor: 'rgba(255, 99, 132, 0.5)',
                borderWidth: 1,
                borderDash: [6, 6],
                label: {
                    content: `Max: ${maxPackets.toFixed(1)} pkt/s`,
                    enabled: true,
                    position: 'right'
                }
            };
            this.packetChart.update();
        }
    }

    showEndpointDetails(endpoint) {
        const endpointData = this.currentEndpoints.find(([addr]) => addr === endpoint)?.[1];
        if (!endpointData) return;
        
        const modal = new bootstrap.Modal(document.getElementById('endpointModal'));
        document.getElementById('endpoint-address').textContent = endpoint;
        
        const portsList = document.getElementById('endpoint-ports').querySelector('ul');
        portsList.innerHTML = endpointData.ports.map(port => 
            `<li>${port}</li>`
        ).join('');
        
        const processesList = document.getElementById('endpoint-processes').querySelector('ul');
        processesList.innerHTML = endpointData.processes.map(process => 
            `<li>${process}</li>`
        ).join('');
        
        document.getElementById('block-endpoint-btn').onclick = () => this.blockEndpoint(endpoint);
        
        modal.show();
    }

    showSuspiciousDetails(ip) {
        const endpoint = this.suspiciousEndpoints.find(ep => ep.ip === ip);
        if (!endpoint) return;
        
        const modal = new bootstrap.Modal(document.getElementById('suspiciousModal'));
        document.getElementById('suspicious-ip').textContent = ip;
        document.getElementById('suspicious-score').textContent = endpoint.score;
        document.getElementById('suspicious-connections').textContent = endpoint.connections;
        document.getElementById('suspicious-ports').textContent = endpoint.ports_targeted;
        
        const flagsList = document.getElementById('suspicious-flags');
        flagsList.innerHTML = endpoint.flags.map(flag => `<li>${flag}</li>`).join('');
        
        document.getElementById('block-suspicious-btn').onclick = () => this.blockEndpoint(ip);
        
        modal.show();
    }

    showAlertDetails(timestamp) {
        // Implementation for showing detailed alert information
        this.showAlert(`Alert details for ${timestamp} would be shown here`, 'info');
    }

    blockEndpoint(endpoint) {
        this.showAlert(`Endpoint ${endpoint} would be blocked in a real implementation`, 'warning');
        
        setTimeout(() => {
            const modal = bootstrap.Modal.getInstance(document.getElementById('endpointModal'));
            if (modal) modal.hide();
            
            const suspiciousModal = bootstrap.Modal.getInstance(document.getElementById('suspiciousModal'));
            if (suspiciousModal) suspiciousModal.hide();
        }, 1500);
    }

    async startMonitoring() {
        try {
            document.getElementById('startBtn').disabled = true;
            document.getElementById('stopBtn').disabled = false;
            
            const response = await fetch('/start');
            const result = await response.json();
            
            if (result.status === 'Monitoring started') {
                this.updateData();
            }
        } catch (error) {
            console.error('Error starting monitoring:', error);
            this.showAlert('Error starting monitoring', 'danger');
        } finally {
            document.getElementById('startBtn').disabled = false;
        }
    }

    async stopMonitoring() {
        try {
            document.getElementById('stopBtn').disabled = true;
            
            const response = await fetch('/stop');
            const result = await response.json();
            
            if (result.status === 'Monitoring stopped') {
                const status = document.getElementById('current-status');
                status.innerHTML = '<i class="bi bi-pause-circle"></i> Monitoring stopped';
                status.className = 'alert alert-secondary mb-0 py-2';
            }
        } catch (error) {
            console.error('Error stopping monitoring:', error);
            this.showAlert('Error stopping monitoring', 'danger');
        } finally {
            document.getElementById('stopBtn').disabled = false;
            document.getElementById('startBtn').disabled = false;
        }
    }

    async generateReport() {
        this.showAlert('Report generation would be implemented here', 'info');
    }

    showAlert(message, type) {
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

    async saveSettings() {
        try {
            const threshold = document.getElementById('thresholdInput').value;
            const alertThreshold = document.getElementById('alertThresholdInput').value;
            const interval = document.getElementById('intervalInput').value;
            
            const response = await fetch('/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    threshold: parseInt(threshold),
                    alert_threshold: parseInt(alertThreshold) / 100,
                    interval: parseInt(interval)
                })
            });
            
            const result = await response.json();
            if (result.success) {
                document.getElementById('threshold-value').textContent = threshold;
                
                if (interval !== this.updateIntervalMs) {
                    this.updateIntervalMs = parseInt(interval);
                    clearInterval(this.updateInterval);
                    this.updateInterval = setInterval(() => this.updateData(), this.updateIntervalMs);
                }
                
                const modal = bootstrap.Modal.getInstance(document.getElementById('settingsModal'));
                if (modal) modal.hide();
                
                this.showAlert('Settings saved successfully', 'success');
            }
        } catch (error) {
            console.error('Error saving settings:', error);
            this.showAlert('Error saving settings', 'danger');
        }
    }
}

// Initialize the monitor
const ddosMonitor = new EnhancedDDoSMonitor();

// Global functions for HTML onclick handlers
function startMonitoring() { ddosMonitor.startMonitoring(); }
function stopMonitoring() { ddosMonitor.stopMonitoring(); }
function saveSettings() { ddosMonitor.saveSettings(); }
function showEndpointDetails(endpoint) { ddosMonitor.showEndpointDetails(endpoint); }
function generateReport() { ddosMonitor.generateReport(); }