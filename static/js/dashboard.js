// static/js/dashboard.js
console.log('Dashboard JS loading...');

// Sample data
const SAMPLE_FEATURES = [
    53.0, 31471.0, 2.0, 2.0, 62.0, 446.0, 31.0, 31.0, 31.0, 0.0,
    223.0, 223.0, 223.0, 0.0, 16141.84487, 127.1011407, 10490.33333,
    18127.37031, 31422.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 48.0,
    48.0, 0.0, 48.0, 48.0, 0.0, 0.0, 0.0, 0.0, 64.0, 64.0,
    63.55057037, 63.55057037, 31.0, 223.0, 107.8, 105.162731,
    11059.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    1.0, 134.75, 31.0, 223.0, 64.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 2.0, 62.0, 2.0, 446.0, -1.0,
    -1.0, 1.0, 32.0, 0.0, 0.0, 0.0, 0.0, 0.0
];

// Analytics data storage
let analyticsData = {
    predictions: [],
    modelStats: {
        'MLP': { requests: 0, responseTime: [], benign: 0, attack: 0, lastUsed: null },
        'LSTM': { requests: 0, responseTime: [], benign: 0, attack: 0, lastUsed: null },
        'Isolation Forest': { requests: 0, responseTime: [], benign: 0, attack: 0, lastUsed: null },
        'Autoencoder Neural Network': { requests: 0, responseTime: [], benign: 0, attack: 0, lastUsed: null }
    },
    charts: {}
};

class CyberSecurityDashboard {
    constructor() {
        this.apiBaseUrl = '/api/v1';
        this.currentTab = 'overview';
        this.activityLog = [];
        this.init();
    }

    init() {
        console.log('Initializing Cybersecurity Dashboard...');
        this.setupNavigation();
        this.loadAutoencoderStatus?.();
        this.refreshDashboard();
        // Initialize threat analytics after a short delay
        setTimeout(() => {
            refreshThreatAnalytics();
        }, 800);
    }

    setupNavigation() {
        console.log('Setting up navigation...');
        document.querySelectorAll('.nav-link').forEach(link => {
        console.log('Dashboard JS loaded successfully (IST timestamps).');
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const href = link.getAttribute('href');
                const target = href.startsWith('#') ? href.substring(1) : href;
                console.log('Switching to tab:', target);
                this.switchTab(target);
                
                // Update active nav link
                document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                link.classList.add('active');
            });
        });
    }

    switchTab(tabId) {
        console.log('Switching to tab:', tabId);
        
        // Hide all tab content
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Show target tab
        const targetTab = document.getElementById(tabId);
        if (targetTab) {
            targetTab.classList.add('active');
            this.currentTab = tabId;
            console.log('Tab switched successfully to:', tabId);
            
            // Load tab-specific content
            if (tabId === 'analytics') {
                refreshThreatAnalytics();
            } else if (tabId === 'threats') {
                loadThreats();
            } else if (tabId === 'securitylogs') {
                loadSecurityLogs();
            }
        } else {
            console.error('Tab not found:', tabId);
        }
    }

    async loadAutoencoderStatus() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/models/status`);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();
            const loaded = data?.models?.autoencoder?.loaded;
            const el = document.getElementById('autoencoder-status');
            if (el) el.textContent = loaded ? 'Online' : 'Offline';
        } catch (e) {
            const el = document.getElementById('autoencoder-status');
            if (el) el.textContent = 'Unknown';
        }
    }

    async loadModelStatus() {
        console.log('Loading model status...');
        try {
            const response = await fetch(`${this.apiBaseUrl}/models/status`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();
            console.log('Model status loaded:', data);
            this.displayModelStatus(data);
        } catch (error) {
            console.error('Failed to load model status:', error);
            this.displayModelStatusError(error);
        }
    }

    displayModelStatus(data) {
        const container = document.getElementById('model-status-container');
        if (!container) {
            console.error('Model status container not found');
            return;
        }
        
        let html = '<div class="row">';
        
        Object.entries(data.models).forEach(([modelName, info]) => {
            const statusClass = info.loaded ? 'success' : 'danger';
            const statusText = info.loaded ? 'Online' : 'Offline';
            const statusIcon = info.loaded ? 'check-circle' : 'times-circle';
            
            html += `
                <div class="col-md-6 mb-3">
                    <div class="card">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <h6 class="card-title">${modelName.toUpperCase()}</h6>
                                    <p class="card-text text-muted">${info.type}</p>
                                    <small class="text-muted">${info.framework}</small>
                                </div>
                                <div class="text-${statusClass}">
                                    <i class="fas fa-${statusIcon} fa-2x"></i>
                                    <div class="small mt-1">${statusText}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        container.innerHTML = html;
    }

    displayModelStatusError(error) {
        const container = document.getElementById('model-status-container');
        if (container) {
            container.innerHTML = `
                <div class="alert alert-danger">
                    <h6><i class="fas fa-exclamation-triangle"></i> Error Loading Model Status</h6>
                    <p>Unable to fetch model status: ${error.message}</p>
                    <button class="btn btn-sm btn-outline-danger" onclick="dashboard.loadModelStatus()">
                        <i class="fas fa-retry"></i> Retry
                    </button>
                </div>
            `;
        }
    }

    async refreshDashboard() {
        console.log('Refreshing dashboard...');
        try {
            await this.loadAutoencoderStatus?.();
            // Also ensure overview shows some recent activity
                    await ensureOverviewRecentActivity();
                console.log('Overview recent activity ensured');
            console.log('Dashboard refreshed successfully');
        } catch (error) {
            console.error('Dashboard refresh failed:', error);
        }
    }

    updateActiveModelsCount() {
        const activeModelsElement = document.getElementById('active-models');
        if (activeModelsElement) {
            activeModelsElement.textContent = '4/4';
        }
    }

    showLoading() {
        console.log('Showing loading modal...');
        const modal = new bootstrap.Modal(document.getElementById('loadingModal'));
        modal.show();
    }

    hideLoading() {
        console.log('Hiding loading modal...');
        const modal = bootstrap.Modal.getInstance(document.getElementById('loadingModal'));
        if (modal) modal.hide();
    }

    addToActivityLog(entry) {
        console.log('Adding to activity log:', entry);
        this.activityLog.unshift({
            timestamp: new Date(),
            ...entry
        });
        
        // Keep only last 10 entries
        this.activityLog = this.activityLog.slice(0, 10);
        this.updateActivityLogDisplay();
        
        // Add to analytics
        this.addAnalyticsEntry(entry.model, entry.prediction, entry.processingTime);
    }

    updateActivityLogDisplay() {
        const tbody = document.getElementById('activity-log');
        if (!tbody) return;
        
        if (this.activityLog.length === 0) {
            // If we previously seeded recent activity from backend, don't overwrite it with a placeholder
            if (tbody.getAttribute('data-seeded') === 'true' && tbody.children.length > 0) {
                return;
            }
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No recent activity</td></tr>';
            return;
        }
        
                tbody.innerHTML = this.activityLog.map(entry => `
                <tr>
                    <td>${entry.timestamp.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}</td>
                    <td>${entry.model}</td>
                    <td>
                        <span class="badge ${entry.prediction === 'BENIGN' ? 'bg-success' : 'bg-warning'}">
                            ${entry.prediction}
                        </span>
                    </td>
                    <td>${entry.processingTime}</td>
                    <td>
                        <span class="badge ${entry.status === 'success' ? 'bg-success' : 'bg-danger'}">
                            ${entry.status}
                        </span>
                    </td>
                </tr>
            `).join('');
    }

    // Analytics functions
    initializeAnalytics() {
        console.log('Initializing analytics...');
        this.loadAnalyticsData();
        this.createCharts();
        this.updateAnalyticsDisplay();
    }

    loadAnalyticsData() {
        const stored = localStorage.getItem('cybersec_analytics');
        if (stored) {
            try {
                const parsedData = JSON.parse(stored);
                analyticsData = { ...analyticsData, ...parsedData };
            } catch (e) {
                console.error('Error loading analytics data:', e);
            }
        }
    }

    saveAnalyticsData() {
        localStorage.setItem('cybersec_analytics', JSON.stringify({
            predictions: analyticsData.predictions,
            modelStats: analyticsData.modelStats
        }));
    }

    addAnalyticsEntry(model, prediction, processingTime) {
        console.log('Adding analytics entry:', { model, prediction, processingTime });
        
        const entry = {
            timestamp: new Date(),
            model,
            prediction,
            processingTime: parseFloat(processingTime)
        };
        
        // Add to predictions array
        analyticsData.predictions.push(entry);
        
        // Keep only last 100 entries
        if (analyticsData.predictions.length > 100) {
            analyticsData.predictions = analyticsData.predictions.slice(-100);
        }
        
        // Update model stats
        if (analyticsData.modelStats[model]) {
            analyticsData.modelStats[model].requests++;
            analyticsData.modelStats[model].responseTime.push(parseFloat(processingTime));
            analyticsData.modelStats[model].lastUsed = new Date();
            
            if (prediction === 'BENIGN') {
                analyticsData.modelStats[model].benign++;
            } else {
                analyticsData.modelStats[model].attack++;
            }
        }
        
        // Save and update display
        this.saveAnalyticsData();
        this.updateAnalyticsDisplay();
        this.updateCharts();
    }

    updateAnalyticsDisplay() {
        console.log('Updating analytics display...');
        
        const totalPredictions = analyticsData.predictions.length;
        const threatsDetected = analyticsData.predictions.filter(p => p.prediction !== 'BENIGN').length;
        const avgResponseTime = totalPredictions > 0 
            ? (analyticsData.predictions.reduce((sum, p) => sum + p.processingTime, 0) / totalPredictions).toFixed(3)
            : 0;
        
        // Update overview cards
        const totalPredictionsEl = document.getElementById('total-predictions');
        const successRateEl = document.getElementById('success-rate');
        const threatsCountEl = document.getElementById('threats-count');
        const avgResponseTimeEl = document.getElementById('avg-response-time');
        
        if (totalPredictionsEl) totalPredictionsEl.textContent = totalPredictions;
        if (successRateEl) successRateEl.textContent = '100%';
        if (threatsCountEl) threatsCountEl.textContent = threatsDetected;
        if (avgResponseTimeEl) avgResponseTimeEl.textContent = avgResponseTime + 's';
        
        // Update detailed table
        this.updateAnalyticsTable();
        
        // Update activity summary
        this.updateActivitySummary();
        
        // Update threat intelligence
        this.updateThreatIntelligence();
    }

    updateAnalyticsTable() {
        const tbody = document.getElementById('analytics-table-body');
        if (!tbody) return;
        
        let html = '';
        
        Object.entries(analyticsData.modelStats).forEach(([model, stats]) => {
            const avgResponseTime = stats.responseTime.length > 0 
                ? (stats.responseTime.reduce((a, b) => a + b, 0) / stats.responseTime.length).toFixed(3)
                : 'N/A';
            
            const successRate = stats.requests > 0 ? '100%' : 'N/A';
            const lastUsed = stats.lastUsed ? new Date(stats.lastUsed).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) : 'Never';
            
            html += `
                <tr>
                    <td><strong>${model}</strong></td>
                    <td>${stats.requests}</td>
                    <td>${avgResponseTime}s</td>
                    <td><span class="badge bg-success">${stats.benign}</span></td>
                    <td><span class="badge bg-warning">${stats.attack}</span></td>
                    <td>${successRate}</td>
                    <td>${lastUsed}</td>
                </tr>
            `;
        });
        
        if (html === '') {
            html = '<tr><td colspan="7" class="text-center text-muted">No analytics data available yet</td></tr>';
        }
        
        tbody.innerHTML = html;
    }

    updateActivitySummary() {
        const container = document.getElementById('activity-summary');
        if (!container) return;
        
        if (analyticsData.predictions.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted">
                    <i class="fas fa-chart-line fa-2x mb-2"></i>
                    <p>Make some predictions to see activity summary</p>
                </div>
            `;
            return;
        }
        
        const recentPredictions = analyticsData.predictions.slice(-10);
        const recentThreats = recentPredictions.filter(p => p.prediction !== 'BENIGN').length;
        const mostUsedModel = Object.entries(analyticsData.modelStats)
            .sort(([,a], [,b]) => b.requests - a.requests)[0];
        
        container.innerHTML = `
            <div class="mb-2">
                <strong>Last 10 Predictions:</strong>
            </div>
            <div class="mb-2">
                <small>Threats Found: <span class="badge bg-warning">${recentThreats}</span></small>
            </div>
            <div class="mb-2">
                <small>Most Used Model: <strong>${mostUsedModel ? mostUsedModel[0] : 'N/A'}</strong></small>
            </div>
            <div>
                <small>Total Sessions: <strong>${analyticsData.predictions.length}</strong></small>
            </div>
        `;
    }

    updateThreatIntelligence() {
        const totalPredictions = analyticsData.predictions.length;
        
        if (totalPredictions === 0) return;
        
        const benignCount = analyticsData.predictions.filter(p => p.prediction === 'BENIGN').length;
        const attackCount = totalPredictions - benignCount;
        
        const benignPercentage = ((benignCount / totalPredictions) * 100).toFixed(1);
        const threatPercentage = ((attackCount / totalPredictions) * 100).toFixed(1);
        
        const benignPercentageEl = document.getElementById('benign-percentage');
        const suspiciousPercentageEl = document.getElementById('suspicious-percentage');
        const threatPercentageEl = document.getElementById('threat-percentage');
        
        if (benignPercentageEl) benignPercentageEl.textContent = benignPercentage + '%';
        if (suspiciousPercentageEl) suspiciousPercentageEl.textContent = '0%';
        if (threatPercentageEl) threatPercentageEl.textContent = threatPercentage + '%';
    }

    createCharts() {
        console.log('Creating charts...');
        this.createPredictionChart();
        this.createPerformanceChart();
        this.createResponseTimeChart();
    }

    createPredictionChart() {
        const ctx = document.getElementById('predictionChart');
        if (!ctx) return;
        
        const predictionCounts = {};
        analyticsData.predictions.forEach(p => {
            predictionCounts[p.prediction] = (predictionCounts[p.prediction] || 0) + 1;
        });
        
        if (analyticsData.charts.prediction) {
            analyticsData.charts.prediction.destroy();
        }
        
        analyticsData.charts.prediction = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(predictionCounts).length > 0 ? Object.keys(predictionCounts) : ['No Data'],
                datasets: [{
                    data: Object.keys(predictionCounts).length > 0 ? Object.values(predictionCounts) : [1],
                    backgroundColor: [
                        '#28a745', // Green for BENIGN
                        '#dc3545', // Red for attacks
                        '#ffc107', // Yellow for warnings
                        '#17a2b8', // Blue for info
                        '#6f42c1'  // Purple for others
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    createPerformanceChart() {
        const ctx = document.getElementById('performanceChart');
        if (!ctx) return;
        
        const modelNames = Object.keys(analyticsData.modelStats);
        const requestCounts = modelNames.map(model => analyticsData.modelStats[model].requests);
        
        if (analyticsData.charts.performance) {
            analyticsData.charts.performance.destroy();
        }
        
        analyticsData.charts.performance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: modelNames,
                datasets: [{
                    label: 'Requests',
                    data: requestCounts,
                    backgroundColor: [
                        '#007bff',
                        '#28a745', 
                        '#ffc107',
                        '#dc3545'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    createResponseTimeChart() {
        const ctx = document.getElementById('responseTimeChart');
        if (!ctx) return;
        
        const last20Predictions = analyticsData.predictions.slice(-20);
        const labels = last20Predictions.map((_, i) => `Request ${i + 1}`);
        const data = last20Predictions.map(p => p.processingTime);
        
        if (analyticsData.charts.responseTime) {
            analyticsData.charts.responseTime.destroy();
        }
        
        analyticsData.charts.responseTime = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels.length > 0 ? labels : ['No Data'],
                datasets: [{
                    label: 'Response Time (s)',
                    data: data.length > 0 ? data : [0],
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Response Time (seconds)'
                        }
                    }
                }
            }
        });
    }

    updateCharts() {
        console.log('Updating charts...');
        this.createCharts(); // Recreate charts with new data
    }

    refreshAnalytics() {
        console.log('Refreshing analytics...');
        this.updateAnalyticsDisplay();
        this.updateCharts();
    }
}

// Global dashboard instance
let dashboard;

// Initialize dashboard when DOM loads
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing dashboard...');
    dashboard = new CyberSecurityDashboard();
});

// Dashboard functions that are called from the HTML
async function refreshDashboard() {
    console.log('Refresh dashboard button clicked');
    if (dashboard) {
        await dashboard.refreshDashboard();
    }
}

// (Removed) sample-data helpers were deprecated with Live Monitor integration

// --- Live monitor integration ---
let _monitorInterval = null;
let _prevStats = { threats_detected: 0, resolved_threats: 0 };
let _prevSampleTs = null;

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function appendMonitorLog(text) {
    const el = document.getElementById('monitor-log');
    if (!el) return;
    const now = nowIST();
    const meta = classifyMonitorMessage(text);
    // Clear placeholder if present
    const isEmpty = el.getAttribute('data-empty') === 'true' || el.textContent.trim() === 'No monitor events yet.';
    if (isEmpty) {
        el.innerHTML = '';
        el.setAttribute('data-empty', 'false');
    }
    const row = document.createElement('div');
    row.className = 'd-flex justify-content-start align-items-center border-bottom py-1';
    row.innerHTML = `
        <span class="badge ${meta.badge} me-2" style="min-width:90px;">${escapeHtml(now)}</span>
        <i class="fas ${meta.icon} me-2 ${meta.cls}"></i>
        <span class="${meta.cls}">${escapeHtml(text)}</span>
    `;
    // Prepend newest on top
    if (el.firstChild) el.insertBefore(row, el.firstChild); else el.appendChild(row);
}

function clearMonitorLog() {
    const el = document.getElementById('monitor-log');
    if (!el) return;
    el.innerHTML = 'No monitor events yet.';
    el.setAttribute('data-empty', 'true');
}

function classifyMonitorMessage(text) {
    const t = String(text).toLowerCase();
    // Error states
    if (t.includes('error') || t.includes('failed')) {
        return { cls: 'text-danger', badge: 'bg-danger', icon: 'fa-triangle-exclamation' };
    }
    // Detection events
    if (t.includes('detected')) {
        return { cls: 'text-danger', badge: 'bg-danger', icon: 'fa-bullseye' };
    }
    // Resolution events
    if (t.includes('automated resolution completed') || t.includes('remediated')) {
        return { cls: 'text-success', badge: 'bg-success', icon: 'fa-check-circle' };
    }
    // Start/stop
    if (t.includes('starting monitor') || t.includes('started')) {
        return { cls: 'text-info', badge: 'bg-info', icon: 'fa-play' };
    }
    if (t.includes('stopping monitor') || t.includes('stopped')) {
        return { cls: 'text-secondary', badge: 'bg-secondary', icon: 'fa-stop' };
    }
    // Backend notices
    if (t.includes('monitor backend')) {
        return { cls: 'text-info', badge: 'bg-info', icon: 'fa-microchip' };
    }
    // Default
    return { cls: 'text-body', badge: 'bg-secondary', icon: 'fa-info-circle' };
}

// Map severity to Bootstrap badge classes
function badgeForSeverity(sev) {
    const s = String(sev || '').toLowerCase();
    if (s === 'low') return 'bg-success';
    if (s === 'medium') return 'bg-warning';
    if (s === 'high') return 'bg-danger';
    if (s === 'critical') return 'bg-dark';
    return 'bg-secondary';
}

// Convert naive UTC ISO timestamps (produced with datetime.utcnow().isoformat()) to IST local display
function isoToISTString(iso) {
    if (!iso) return '-';
    const fixed = /Z$/.test(iso) ? iso : iso + 'Z'; // treat as UTC then show Asia/Kolkata
    const d = new Date(fixed);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
}
function nowIST() {
    return new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata' });
}

async function pollMonitorStats() {
    try {
    const res = await fetch('/web/dashboard/api/stats');
        if (!res.ok) throw new Error('Stats fetch failed');
        const data = await res.json();
        const sec = data.security || {};

        // Update resolved count UI
        const resolvedEl = document.getElementById('resolved-threats');
        if (resolvedEl) resolvedEl.textContent = String(sec.resolved_threats || 0);

    const resolvedOverviewEl = document.getElementById('remediated-count');
    if (resolvedOverviewEl) resolvedOverviewEl.textContent = String(sec.resolved_threats || 0);

        const activeEl = document.getElementById('active-threats');
        if (activeEl) activeEl.textContent = String(sec.active_threats || 0);

        // Update threats detected badge on overview
    const threatsEl = document.getElementById('threats-detected');
    if (threatsEl) threatsEl.textContent = String(sec.threats_detected || 0);

        // Detect new events
        const newThreats = (sec.threats_detected || 0) - (_prevStats.threats_detected || 0);
        const newResolved = (sec.resolved_threats || 0) - (_prevStats.resolved_threats || 0);

        if (newThreats > 0) {
            appendMonitorLog(`Detected ${newThreats} new threat(s). Attempting automated resolution...`);
        }

        if (newResolved > 0) {
            appendMonitorLog(`Automated resolution completed for ${newResolved} threat(s).`);
            // Add activity log entry for visibility
            if (window.dashboard) {
                dashboard.addToActivityLog({
                    model: 'Autoencoder Neural Network',
                    prediction: 'ATTACK',
                    processingTime: '0.0',
                    status: 'resolved'
                });
            }
        }

        _prevStats.threats_detected = sec.threats_detected || 0;
        _prevStats.resolved_threats = sec.resolved_threats || 0;

        // Update last-event field and system health
        const last = sec.last_activity || '-';
        const lastEl = document.getElementById('monitor-last-event');
        if (lastEl) lastEl.textContent = last;

        const shText = document.getElementById('system-health-text');
        const shCard = document.getElementById('system-health-card');
        const active = sec.active_threats || 0;
        if (shText && shCard) {
            if (active > 0) {
                shText.textContent = 'Alert';
                shCard.classList.remove('bg-info');
                shCard.classList.add('bg-danger');
            } else {
                shText.textContent = 'Healthy';
                shCard.classList.remove('bg-danger');
                shCard.classList.add('bg-info');
            }
        }

        // Show/hide the live monitor "View Active Threats" button
        const goBtn = document.getElementById('monitor-threats-button');
        if (goBtn) {
            if ((sec.active_threats || 0) > 0 || newThreats > 0) {
                goBtn.style.display = 'inline-block';
            } else {
                goBtn.style.display = 'none';
            }
        }

        // Continuous safe/alert updates from system monitor samples
        const sm = data.system_monitor || null;
        if (sm && sm.timestamp) {
            if (_prevSampleTs !== sm.timestamp) {
                _prevSampleTs = sm.timestamp;
                const ts = new Date(sm.timestamp * 1000).toLocaleTimeString();
                if (sm.suspicious) {
                    appendMonitorLog(`System monitor alert: high network activity (conn=${(sm.metrics?.conn_total)||0}, remotes=${(sm.metrics?.unique_remotes)||0})`);
                } else {
                    appendMonitorLog(`System monitor heartbeat: safe (tx=${Math.round((sm.metrics?.bytes_sent_rate||0)/1e6)}MB/s, rx=${Math.round((sm.metrics?.bytes_recv_rate||0)/1e6)}MB/s)`);
                }
            }
        }

    } catch (e) {
        console.error('Monitor poll failed', e);
        appendMonitorLog('Monitor polling error: ' + e.message);
    }
}

// --- Overview recent activity seeding ---
async function ensureOverviewRecentActivity() {
    try {
        const tbody = document.getElementById('activity-log');
        if (!tbody) return;
        const hasEntries = (dashboard && Array.isArray(dashboard.activityLog) && dashboard.activityLog.length > 0);
        const isPlaceholder = tbody.textContent && tbody.textContent.includes('No recent activity');
    if (hasEntries && !isPlaceholder) return; // nothing to do

        // Fetch a few recent threats to display something meaningful
        const res = await fetch('/api/v1/threats?limit=5&offset=0');
        if (!res.ok) throw new Error('Failed to fetch recent threats');
        const data = await res.json();
        const items = (data.items || []).slice(0, 5);
        if (items.length === 0) {
            // Fall back to a single heartbeat row
            tbody.innerHTML = `
                <tr>
                    <td>${nowIST()}</td>
                    <td>-</td>
                    <td><span class="badge bg-info">Heartbeat</span></td>
                    <td>-</td>
                    <td><span class="badge bg-secondary">idle</span></td>
                </tr>
            `;
            tbody.setAttribute('data-seeded', 'true');
            return;
        }
        // Render recent threats into the overview table
        tbody.innerHTML = items.map(t => `
            <tr>
                <td>${isoToISTString(t.timestamp)}</td>
                <td>${(t.model || t.type || '-')}</td>
                <td><span class="badge ${t.status === 'active' ? 'bg-warning' : 'bg-success'}">${t.type || 'ATTACK'}</span></td>
                <td>-</td>
                <td><span class="badge ${t.status === 'active' ? 'bg-danger' : 'bg-success'}">${t.status}</span></td>
            </tr>
        `).join('');
        tbody.setAttribute('data-seeded', 'true');
    } catch (e) {
        console.error('Failed to seed overview activity', e);
    }
}

function startMonitor() {
    const startBtn = document.getElementById('monitor-start');
    const stopBtn = document.getElementById('monitor-stop');
    const statusEl = document.getElementById('monitor-status');
    const modeSel = document.getElementById('monitor-mode');
    const mode = (modeSel && modeSel.value === 'log') ? 'log' : 'system';
        if (startBtn) startBtn.disabled = true;
        if (stopBtn) stopBtn.disabled = false;
        if (statusEl) statusEl.textContent = 'Running';
        appendMonitorLog('Starting monitor (mode: ' + (mode === 'log' ? 'log-only' : 'system+log') + ')...');
        _prevStats = { threats_detected: 0, resolved_threats: 0 };
        // Ask backend to start tailing the log
        const url = mode === 'log' ? '/web/dashboard/api/monitor/start?source=log' : '/web/dashboard/api/monitor/start';
        fetch(url, { method: 'POST' })
            .then(r => r.json()).then(data => {
                appendMonitorLog('Monitor backend: ' + (data.status || 'unknown'));
            }).catch(err => {
                console.error('Failed to start backend monitor', err);
                appendMonitorLog('Failed to start backend monitor: ' + err.message);
            });
        // Start polling every 2 seconds
        _monitorInterval = setInterval(pollMonitorStats, 2000);
        // Do an immediate poll
        pollMonitorStats();
}

function stopMonitor() {
    const startBtn = document.getElementById('monitor-start');
    const stopBtn = document.getElementById('monitor-stop');
    const statusEl = document.getElementById('monitor-status');
    if (startBtn) startBtn.disabled = false;
    if (stopBtn) stopBtn.disabled = true;
    if (statusEl) statusEl.textContent = 'Stopped';
        appendMonitorLog('Stopping monitor...');
        // Ask backend to stop tailing the log
        fetch('/web/dashboard/api/monitor/stop', { method: 'POST' })
            .then(r => r.json()).then(data => {
                appendMonitorLog('Monitor backend: ' + (data.status || 'unknown'));
            }).catch(err => {
                console.error('Failed to stop backend monitor', err);
                appendMonitorLog('Failed to stop backend monitor: ' + err.message);
            });
    if (_monitorInterval) clearInterval(_monitorInterval);
    _monitorInterval = null;
}

// --- Threats management frontend helpers (lightweight) ---
function navigateThreats(filter) {
    const link = document.querySelector('a.nav-link[href="#threats"]');
    if (link) link.click();
    if (filter === 'active') document.getElementById('filter-status').value = 'active';
    else if (filter === 'remediated') document.getElementById('filter-status').value = 'remediated';
    else document.getElementById('filter-status').value = '';
    setTimeout(loadThreats, 150);
}

async function loadThreats() {
    const status = document.getElementById('filter-status')?.value || '';
    const severity = document.getElementById('filter-severity')?.value || '';
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);
    const res = await fetch(`/api/v1/threats?${params.toString()}`);
    const data = await res.json();
    const tbody = document.getElementById('threats-table');
    const cnt = document.getElementById('threats-count');
    if (cnt) cnt.textContent = `${data.total} total`;
    if (!tbody) return;
    if (!data.items || data.items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No data</td></tr>';
        return;
    }
    // Ensure newest-first ordering on the client as well (defensive)
    const items = (data.items || []).slice().sort((a, b) => {
        const ta = new Date(a.timestamp || 0).getTime();
        const tb = new Date(b.timestamp || 0).getTime();
        return tb - ta;
    });
    tbody.innerHTML = items.map(t => `
        <tr>
            <td>${isoToISTString(t.timestamp)}</td>
            <td>${t.type}</td>
            <td><span class="badge ${badgeForSeverity(t.severity)}">${t.severity}</span></td>
            <td><span class="badge ${t.status === 'active' ? 'bg-danger' : 'bg-success'}">${t.status}</span></td>
            <td class="text-end">
                <button class="btn btn-sm btn-outline-primary" onclick="showThreatDetail('${t.id}')">View</button>
            </td>
        </tr>
    `).join('');
}

async function purgeOldestThreats() {
    const inp = document.getElementById('purge-count');
    const n = parseInt(inp?.value || '300', 10);
    if (!n || n < 1) { alert('Enter a valid count'); return; }
    if (!confirm(`Remove the oldest ${n} threat records? This cannot be undone.`)) return;
    try {
        const res = await fetch('/api/v1/admin/purge-oldest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ count: n, confirm: true })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Purge failed');
        appendMonitorLog(`Purge oldest completed: removed ${data.removed}/${data.requested}`);
        // Refresh tables and analytics
        await loadThreats();
        await refreshThreatAnalytics();
        alert(`Removed ${data.removed} oldest threat(s).`);
    } catch (e) {
        console.error(e);
        alert('Error purging threats: ' + e.message);
    }
}

// Show threat details in the side panel and provide labeling/outcome controls
async function showThreatDetail(id) {
    try {
        const res = await fetch(`/api/v1/threats/${id}`);
        if (!res.ok) throw new Error('Failed to fetch threat');
        const t = await res.json();
        const container = document.getElementById('threat-detail');
        if (!container) return;

        const actions = (t.actions || []).map(a => `
            <li><code>${isoToISTString(a.timestamp)}</code> - ${a.action} (${a.result}) ${a.notes ? '- ' + a.notes : ''}</li>
        `).join('');

        const remediateBtn = t.status === 'active'
            ? `<button class="btn btn-sm btn-success me-2" onclick="remediateThreat('${t.id}')"><i class="fas fa-wrench"></i> Remediate</button>`
            : '';

        const labelBadgeClass = t.label === 'tp' ? 'bg-success' : (t.label === 'fp' ? 'bg-secondary' : 'bg-light text-dark');
        const outcomeBadgeClass = t.outcome === 'contained' ? 'bg-info' : (t.outcome === 'recurring' ? 'bg-warning' : 'bg-light text-dark');

            container.innerHTML = `
                <div class="mb-2"><strong>ID:</strong> ${t.id}</div>
                <div class="mb-2"><strong>Type:</strong> ${t.type} <span class="badge ${badgeForSeverity(t.severity)}">${t.severity}</span></div>
                <div class="mb-2"><strong>Time (IST):</strong> ${isoToISTString(t.timestamp)}</div>
                <div class="mb-2"><strong>Status:</strong> <span class="badge ${t.status === 'active' ? 'bg-danger' : 'bg-success'}">${t.status}</span></div>
            <div class="mb-2"><strong>Source:</strong> ${t.source_ip || '-'} <strong class="ms-2">Endpoint:</strong> ${t.endpoint || '-'}</div>
            <div class="mb-2"><strong>Details:</strong><pre style="white-space: pre-wrap;">${escapeHtml(JSON.stringify(t.details || {}, null, 2))}</pre></div>
            <div class="mb-2"><strong>Actions:</strong><ul class="mb-2">${actions || '<li class="text-muted">None</li>'}</ul></div>
            <div class="d-flex align-items-center mb-2">
                ${remediateBtn}
                <div class="btn-group btn-group-sm" role="group" aria-label="Label threat">
                    <button class="btn btn-outline-success" onclick="labelThreat('${t.id}','tp')">Mark TP</button>
                    <button class="btn btn-outline-secondary" onclick="labelThreat('${t.id}','fp')">Mark FP</button>
                </div>
            </div>
            <div class="mb-1"><small class="text-muted">Current Label:</small> <span class="badge ${labelBadgeClass}">${t.label || 'unlabeled'}</span></div>
            <div class="d-flex align-items-center mt-2">
                <div class="btn-group btn-group-sm" role="group" aria-label="Outcome">
                    <button class="btn btn-outline-info" onclick="setThreatOutcome('${t.id}','contained')">Contained</button>
                    <button class="btn btn-outline-warning" onclick="setThreatOutcome('${t.id}','recurring')">Recurring</button>
                </div>
            </div>
            <div class="mt-1"><small class="text-muted">Outcome:</small> <span class="badge ${outcomeBadgeClass}">${t.outcome || 'unknown'}</span></div>
        `;
    } catch (e) {
        console.error(e);
        alert('Failed to load threat details: ' + e.message);
    }
}

async function labelThreat(id, label) {
    try {
        const res = await fetch(`/api/v1/threats/${id}/label`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ label })
        });
        if (!res.ok) throw new Error('Failed to label threat');
        appendMonitorLog(`Threat labeled: ${id} (${label})`);
        await showThreatDetail(id);
        await refreshThreatAnalytics();
    } catch (e) {
        console.error(e);
        alert('Labeling failed: ' + e.message);
    }
}

async function setThreatOutcome(id, outcome) {
    try {
        const res = await fetch(`/api/v1/threats/${id}/outcome`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ outcome })
        });
        if (!res.ok) throw new Error('Failed to set outcome');
        appendMonitorLog(`Threat outcome set: ${id} (${outcome})`);
        await showThreatDetail(id);
        await refreshThreatAnalytics();
    } catch (e) {
        console.error(e);
        alert('Outcome update failed: ' + e.message);
    }
}

async function remediateThreat(id) {
    const res = await fetch(`/api/v1/threats/${id}/remediate`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ notes: 'Manual remediation from UI' })});
    if (res.ok) {
        loadThreats();
        appendMonitorLog('Threat remediated: ' + id);
        // Clear selected threat details and notify user
        const container = document.getElementById('threat-detail');
        if (container) container.innerHTML = '<div class="text-muted">Select a threat to view details</div>';
        try { alert('Threat remediated successfully.'); } catch (_) {}
    }
}

async function quickNetworkScan() {
    const out = document.getElementById('quick-actions-output');
    if (out) out.textContent = 'Running network scan...';
    const res = await fetch('/api/v1/threats/quick/network-scan', { method: 'POST' });
    const data = await res.json();
    if (out) out.textContent = JSON.stringify(data, null, 2);
}

async function quickLogAnalysis() {
    const out = document.getElementById('quick-actions-output');
    if (out) out.textContent = 'Analyzing logs...';
    const res = await fetch('/api/v1/threats/quick/log-analysis', { method: 'POST' });
    const data = await res.json();
    if (out) out.textContent = JSON.stringify(data, null, 2);
}

async function loadSecurityLogs() {
    const pre = document.getElementById('security-logs');
    if (pre) pre.textContent = 'Loading...';
    const res = await fetch('/api/v1/logs/security');
    const data = await res.json();
    if (pre) pre.textContent = (data.lines || []).join('\n');
}

async function classifyThreat() {
    console.log('Classify threat button clicked');
    
    const modelSelect = document.getElementById('model-select');
    const featuresInput = document.getElementById('features-input');
    
    if (!modelSelect || !featuresInput) {
        console.error('Required elements not found');
        alert('Error: Required form elements not found');
        return;
    }
    
    const modelType = modelSelect.value;
    const featuresText = featuresInput.value;
    
    if (!featuresText.trim()) {
        alert('Please enter feature values or load sample data');
        return;
    }
    
    try {
        const features = featuresText.split(',').map(f => parseFloat(f.trim()));
        if (features.length !== 75) {
            alert(`Expected 75 features, got ${features.length}`);
            return;
        }
        
        console.log('Making classification request...', { modelType, featuresCount: features.length });
        
        if (dashboard) {
            dashboard.showLoading();
        }
        
        const response = await fetch(`/api/v1/predict/classification/${modelType}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ features })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        console.log('Classification result:', result);
        displayClassificationResult(result);
        
        if (dashboard) {
            dashboard.addToActivityLog({
                model: result.model_used,
                prediction: result.prediction,
                processingTime: `${result.processing_time}s`,
                status: result.status
            });
        }
        
    } catch (error) {
        console.error('Classification error:', error);
        alert('Classification failed: ' + error.message);
    } finally {
        if (dashboard) {
            dashboard.hideLoading();
        }
    }
}

// --- Threat Analytics ---
let _chartStatus = null, _chartSeverity = null, _chartTrend = null;

async function refreshThreatAnalytics() {
    try {
        const res = await fetch('/api/v1/analytics/threats');
        const data = await res.json();
        const totals = data.totals || {};

        // KPIs
        const kTotal = document.getElementById('kpi-total');
        const kActive = document.getElementById('kpi-active');
        const kRem = document.getElementById('kpi-remediated');
        const kMttr = document.getElementById('kpi-mttr');
        if (kTotal) kTotal.textContent = String(totals.total || 0);
        if (kActive) kActive.textContent = String(totals.active || 0);
        if (kRem) kRem.textContent = String(totals.remediated || 0);
        if (kMttr) kMttr.textContent = (data.mttr_seconds ? data.mttr_seconds + 's' : 'N/A');

        // Charts
        renderStatusChart(totals);
        renderSeverityChart(data.severity || {});
        renderTrendChart(data.trend || []);

        // Recent threats table
        const listRes = await fetch('/api/v1/threats?limit=10&offset=0');
        const listData = await listRes.json();
        const tbody = document.getElementById('analytics-recent-body');
        if (tbody) {
            const items = listData.items || [];
            if (items.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No data</td></tr>';
            } else {
                tbody.innerHTML = items.map(t => `
                    <tr>
                        <td>${isoToISTString(t.timestamp)}</td>
                        <td>${t.type}</td>
                        <td><span class="badge ${badgeForSeverity(t.severity)}">${t.severity}</span></td>
                        <td><span class="badge ${t.status === 'active' ? 'bg-danger' : 'bg-success'}">${t.status}</span></td>
                    </tr>
                `).join('');
            }
        }
    } catch (e) {
        console.error('Failed to refresh threat analytics', e);
    }
}

function renderStatusChart(totals) {
    const ctx = document.getElementById('chart-status');
    if (!ctx) return;
    if (_chartStatus) _chartStatus.destroy();
    const active = totals.active || 0;
    const rem = totals.remediated || 0;
    _chartStatus = new Chart(ctx, {
        type: 'doughnut',
        data: { labels: ['Active', 'Remediated'], datasets: [{ data: [active, rem], backgroundColor: ['#dc3545', '#28a745'] }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
    });
}

function renderSeverityChart(severity) {
    const ctx = document.getElementById('chart-severity');
    if (!ctx) return;
    if (_chartSeverity) _chartSeverity.destroy();
    const labels = Object.keys(severity);
    const values = labels.map(k => severity[k]);
    _chartSeverity = new Chart(ctx, {
        type: 'bar',
        data: { labels, datasets: [{ label: 'Threats', data: values, backgroundColor: '#ffc107' }] },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
    });
}

function renderTrendChart(trend) {
    const ctx = document.getElementById('chart-trend');
    if (!ctx) return;
    if (_chartTrend) _chartTrend.destroy();
    const labels = trend.map(x => x.date);
    const totals = trend.map(x => x.total);
    const actives = trend.map(x => x.active);
    const rems = trend.map(x => x.remediated);
    _chartTrend = new Chart(ctx, {
        type: 'line',
        data: { labels, datasets: [
            { label: 'Total', data: totals, borderColor: '#0d6efd', backgroundColor: 'rgba(13,110,253,0.1)', tension: 0.3, fill: true },
            { label: 'Active', data: actives, borderColor: '#dc3545', backgroundColor: 'rgba(220,53,69,0.1)', tension: 0.3, fill: true },
            { label: 'Remediated', data: rems, borderColor: '#28a745', backgroundColor: 'rgba(40,167,69,0.1)', tension: 0.3, fill: true },
        ] },
        options: { responsive: true, maintainAspectRatio: false }
    });
}

function exportThreatAnalytics() {
    // Fetch current analytics and download JSON
    fetch('/api/v1/analytics/threats').then(r => r.json()).then(data => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `threat_analytics_${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });
}


async function simulateAttack() {
    console.log('Simulate attack button clicked');
    
    const entryPoint = document.getElementById('entry-point')?.value;
    const attackType = document.getElementById('attack-type')?.value;
    const maxSteps = parseInt(document.getElementById('max-steps')?.value);
    
    if (!entryPoint || !attackType || !maxSteps) {
        alert('Please fill in all simulation parameters');
        return;
    }
    
    try {
        console.log('Making attack simulation request...', { entryPoint, attackType, maxSteps });
        
        if (dashboard) {
            dashboard.showLoading();
        }
        
        const response = await fetch('/api/v1/simulation/simulate-attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                entry_point: entryPoint,
                attack_type: attackType,
                max_steps: maxSteps
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        console.log('Attack simulation result:', result);
        displaySimulationResult(result);
        
    } catch (error) {
        console.error('Simulation error:', error);
        alert('Attack simulation failed: ' + error.message);
    } finally {
        if (dashboard) {
            dashboard.hideLoading();
        }
    }
}

async function refreshAnalytics() {
    console.log('Refreshing analytics (threats stats)...');
    try {
        const res = await fetch('/api/v1/statistics/threats');
        const stats = await res.json();
        // Map to overview cards in analytics
        const totalEl = document.getElementById('total-predictions');
        const successEl = document.getElementById('success-rate');
        const threatsEl = document.getElementById('threats-count');
        const avgRtEl = document.getElementById('avg-response-time');
        if (totalEl) totalEl.textContent = String(stats.total || 0);
        const rem = stats.remediated || 0;
        const tot = stats.total || 0;
        const rate = tot > 0 ? Math.round((rem / tot) * 100) + '%' : '0%';
        if (successEl) successEl.textContent = rate;
        if (threatsEl) threatsEl.textContent = String(stats.active || 0);
        if (avgRtEl) avgRtEl.textContent = 'N/A';

        // Update threats overview widget
        const aEl = document.getElementById('th-overview-active');
        const tEl = document.getElementById('th-overview-total');
        const rEl = document.getElementById('th-overview-remediated');
        const pEl = document.getElementById('th-overview-progress');
        if (aEl) aEl.textContent = String(stats.active || 0);
        if (tEl) tEl.textContent = String(stats.total || 0);
        if (rEl) rEl.textContent = String(stats.remediated || 0);
        if (pEl) {
            const pct = (stats.total || 0) > 0 ? Math.round(((stats.active || 0) / stats.total) * 100) : 0;
            pEl.style.width = pct + '%';
        }
    } catch (e) {
        console.error('Analytics refresh failed', e);
    }
}

async function exportAnalytics() {
    console.log('Exporting analytics...');
    
    const data = {
        generated: new Date().toISOString(),
        totalPredictions: analyticsData.predictions.length,
        modelStatistics: analyticsData.modelStats,
        predictions: analyticsData.predictions
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybersec_analytics_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    alert('Analytics report exported successfully!');
}

function displayClassificationResult(result) {
    const container = document.getElementById('classification-results');
    if (!container) {
        console.error('Classification results container not found');
        return;
    }
    
    const alertClass = result.prediction === 'BENIGN' ? 'success' : 'warning';
    const icon = result.prediction === 'BENIGN' ? 'check-circle' : 'exclamation-triangle';
    
    container.innerHTML = `
        <div class="alert alert-${alertClass} fade-in">
            <h6><i class="fas fa-${icon}"></i> Classification Result</h6>
            <div class="row">
                <div class="col-sm-6">
                    <strong>Prediction:</strong> 
                    <span class="badge bg-${alertClass} ms-2">${result.prediction}</span>
                </div>
                <div class="col-sm-6">
                    <strong>Model:</strong> ${result.model_used}
                </div>
                <div class="col-sm-6">
                    <strong>Processing Time:</strong> ${result.processing_time}s
                </div>
                <div class="col-sm-6">
                    <strong>Status:</strong> 
                    <span class="badge bg-success">${result.status}</span>
                </div>
            </div>
        </div>
    `;
}

function displayAnomalyResult(result) {
    const container = document.getElementById('anomaly-results');
    if (!container) {
        console.error('Anomaly results container not found');
        return;
    }
    
    const alertClass = result.prediction === 'BENIGN' ? 'success' : 'danger';
    const icon = result.prediction === 'BENIGN' ? 'check-circle' : 'exclamation-triangle';
    
    container.innerHTML = `
        <div class="alert alert-${alertClass} fade-in">
            <h6><i class="fas fa-${icon}"></i> Anomaly Detection Result</h6>
            <div class="row">
                <div class="col-sm-6">
                    <strong>Result:</strong> 
                    <span class="badge bg-${alertClass} ms-2">${result.prediction}</span>
                </div>
                <div class="col-sm-6">
                    <strong>Model:</strong> ${result.model_used}
                </div>
                <div class="col-sm-6">
                    <strong>Processing Time:</strong> ${result.processing_time}s
                </div>
                <div class="col-sm-6">
                    <strong>Status:</strong> 
                    <span class="badge bg-success">${result.status}</span>
                </div>
            </div>
        </div>
    `;
}

function displaySimulationResult(result) {
    const container = document.getElementById('simulation-results');
    if (!container) {
        console.error('Simulation results container not found');
        return;
    }
    
    let pathsHtml = result.possible_paths.map(path => `
        <div class="path-item">
            <div class="d-flex justify-content-between align-items-start mb-2">
                <div>
                    <strong>Path:</strong> ${path.path.join(' → ')}
                </div>
                <span class="badge bg-warning">Risk: ${(path.risk_score * 100).toFixed(0)}%</span>
            </div>
            <div class="row">
                <div class="col-sm-6">
                    <small><strong>Probability:</strong> ${(path.probability * 100).toFixed(0)}%</small>
                </div>
                <div class="col-sm-6">
                    <small><strong>Est. Time:</strong> ${path.estimated_time}</small>
                </div>
            </div>
            <div class="mt-2">
                <small><strong>MITRE Techniques:</strong></small><br>
                ${path.techniques.map(t => `<span class="badge bg-secondary technique-badge">${t}</span>`).join('')}
            </div>
        </div>
    `).join('');
    
    container.innerHTML = `
        <div class="fade-in">
            <div class="alert alert-info">
                <h6><i class="fas fa-info-circle"></i> Simulation: ${result.simulation_id}</h6>
                <p class="mb-0">Entry Point: <strong>${result.entry_point}</strong> | 
                Attack Type: <strong>${result.attack_type}</strong></p>
                <div class="mt-2">
                    <button class="btn btn-sm btn-outline-primary" onclick="injectThreatFromSimulation('${result.entry_point}','${result.attack_type}')">
                        <i class="fas fa-plus-circle"></i> Create Test Threat
                    </button>
                </div>
            </div>
            
            <h6>Attack Paths (${result.possible_paths.length})</h6>
            ${pathsHtml}
            
            <div class="mt-3">
                <h6>Critical Assets at Risk</h6>
                <div class="mb-2">
                    ${result.critical_assets_at_risk.map(asset => 
                        `<span class="badge bg-danger me-1">${asset}</span>`
                    ).join('')}
                </div>
            </div>
            
            <div class="mt-3">
                <h6>Recommended Defenses</h6>
                <ul class="list-unstyled">
                    ${result.recommended_defenses.map(defense => 
                        `<li><i class="fas fa-shield-alt text-success"></i> ${defense}</li>`
                    ).join('')}
                </ul>
            </div>
        </div>
    `;
}

async function injectThreatFromSimulation(entryPoint, attackType) {
    try {
        const res = await fetch('/api/v1/simulation/inject-threat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ entry_point: entryPoint, attack_type: attackType })
        });
        if (!res.ok) throw new Error('Failed to inject threat');
        const data = await res.json();
        const th = data?.threat || {};
        const wasAuto = !!data?.auto_remediated || (th.status === 'remediated');
        let alertMsg;
        if (wasAuto) {
            appendMonitorLog(`Injected test threat auto-remediated: ${attackType} (${th.id || ''})`);
            alertMsg = 'Test threat was auto-remediated by the agent. Redirecting to Live Monitor...';
        } else {
            appendMonitorLog(`Injected test threat: ${attackType} (${th.id || ''})`);
            alertMsg = 'Test threat injected. Redirecting to Live Monitor...';
        }
        try { alert(alertMsg); } catch (_) {}
        // Redirect to Live Monitor tab after user acknowledges alert
        const liveLink = document.querySelector('a.nav-link[href="#anomaly"]');
        if (liveLink) liveLink.click(); else if (window.dashboard) dashboard.switchTab('anomaly');
    } catch (e) {
        console.error(e);
        appendMonitorLog('Inject threat error: ' + e.message);
    }
}

console.log('Dashboard JS loaded successfully!');
