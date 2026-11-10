/**
 * Evil Twin Detector - Dashboard JavaScript
 * Handles scanning, real-time updates, network display, and user interactions.
 */

// ─────────────────────────────────────
// State
// ─────────────────────────────────────
let currentNetworks = [];
let renderedNetworks = [];   // rows currently shown in the table (after filtering)
let currentFilter = 'all';
let isScanning = false;
let pollInterval = null;

// ─────────────────────────────────────
// Scanning
// ─────────────────────────────────────

async function startScan() {
    if (isScanning) return;

    const btn = document.getElementById('btnScan');
    const btnText = document.getElementById('btnScanText');
    const scanAnim = document.getElementById('scanAnimation');
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');

    // Update UI to scanning state
    isScanning = true;
    btn.classList.add('scanning');
    btnText.textContent = 'Scanning...';
    scanAnim.style.display = 'flex';
    statusDot.classList.add('scanning');
    statusText.textContent = 'Scanning...';

    try {
        // Trigger scan
        const response = await fetch('/api/scan', { method: 'POST' });
        const data = await response.json();

        if (data.status === 'ok') {
            // Poll for results
            pollForResults();
        } else {
            showError(data.message || 'Failed to start scan');
            resetScanUI();
        }
    } catch (error) {
        console.error('Scan error:', error);
        showError('Failed to connect to the server');
        resetScanUI();
    }
}

function pollForResults() {
    let attempts = 0;
    const maxAttempts = 60; // 30 seconds max

    pollInterval = setInterval(async () => {
        attempts++;

        try {
            const response = await fetch('/api/scan/status');
            const status = await response.json();

            // Update scan status text
            const statusText = document.getElementById('scanStatusText');
            if (statusText) {
                const messages = [
                    'Scanning nearby networks...',
                    'Analyzing beacon frames...',
                    'Checking for SSID duplicates...',
                    'Evaluating encryption types...',
                    'Computing risk scores...',
                    'Finalizing analysis...'
                ];
                statusText.textContent = messages[Math.min(attempts - 1, messages.length - 1)];
            }

            if (!status.is_scanning) {
                // Scan complete
                clearInterval(pollInterval);
                await loadNetworks();
                await loadStatistics();
                resetScanUI();
                showSuccess(`Scan complete! Found ${status.network_count} networks, ${status.alert_count} alerts.`);
            }
        } catch (error) {
            console.error('Poll error:', error);
        }

        if (attempts >= maxAttempts) {
            clearInterval(pollInterval);
            resetScanUI();
            showError('Scan timed out');
        }
    }, 500);
}

function resetScanUI() {
    isScanning = false;
    const btn = document.getElementById('btnScan');
    const btnText = document.getElementById('btnScanText');
    const scanAnim = document.getElementById('scanAnimation');
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');

    if (btn) btn.classList.remove('scanning');
    if (btnText) btnText.textContent = 'Start Scan';
    if (scanAnim) scanAnim.style.display = 'none';
    if (statusDot) statusDot.classList.remove('scanning');
    if (statusText) statusText.textContent = 'Ready';
}

// ─────────────────────────────────────
// Data Loading
// ─────────────────────────────────────

async function loadNetworks() {
    try {
        const response = await fetch('/api/networks');
        const data = await response.json();
        currentNetworks = data.networks || [];
        updateModeNotice(data.scan_mode, data.scan_note);
        renderNetworks(currentNetworks);
        updateThreatBanner(currentNetworks);
        updateAlerts();
    } catch (error) {
        console.error('Failed to load networks:', error);
    }
}

async function loadStatistics() {
    try {
        const response = await fetch('/api/statistics');
        const stats = await response.json();

        updateElement('statTotalNetworks', stats.unique_networks || 0);
        updateElement('statHighRisk', stats.high_risk_detections || 0);
        updateElement('statMediumRisk', stats.total_alerts || 0);
        updateElement('statTotalScans', stats.total_scans || 0);
    } catch (error) {
        console.error('Failed to load statistics:', error);
    }
}

async function updateAlerts() {
    try {
        const response = await fetch('/api/alerts');
        const data = await response.json();
        renderAlerts(data.alerts || []);
    } catch (error) {
        console.error('Failed to load alerts:', error);
    }
}

// ─────────────────────────────────────
// Rendering
// ─────────────────────────────────────

function renderNetworks(networks) {
    const tbody = document.getElementById('networksTableBody');
    if (!tbody) return;

    // Apply filter
    let filtered = networks;
    if (currentFilter !== 'all') {
        filtered = networks.filter(n => n.risk_level === currentFilter);
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="9">
                    <div class="empty-state">
                        <p>${currentFilter !== 'all' ? 'No ' + currentFilter + ' risk networks found.' : 'No networks scanned yet. Click <strong>Start Scan</strong> to begin.'}</p>
                    </div>
                </td>
            </tr>`;
        return;
    }

    // Rows carry only an index; the click handler below looks the network up.
    // Previously SSIDs were placed inside inline onclick="addToWhitelist('...')"
    // handlers. escapeHtml() turns ' into &#039;, but the browser decodes that
    // back to ' before running the handler, so an attacker-chosen SSID such as
    //   ');alert(document.cookie)//
    // could break out of the string and run script in the dashboard.
    renderedNetworks = filtered;
    tbody.innerHTML = filtered.map((network, index) => `
        <tr class="network-row" data-risk="${network.risk_level}">
            <td><span class="risk-dot ${network.risk_level}"></span></td>
            <td>
                <strong>${escapeHtml(network.ssid)}</strong>
                ${network.duplicate_count > 1 ? `<span class="badge badge-high" style="margin-left:6px; font-size:0.65rem;">×${network.duplicate_count}</span>` : ''}
            </td>
            <td><span class="mono">${escapeHtml(network.bssid)}</span></td>
            <td>${renderSignalBar(network.signal_strength)}</td>
            <td>${network.channel} <span class="text-muted">(${network.frequency})</span></td>
            <td>
                <span class="badge ${network.encryption === 'Open' ? 'badge-high' : 'badge-low'}">
                    ${escapeHtml(network.encryption)}
                </span>
            </td>
            <td><span class="text-muted">${escapeHtml(network.vendor || 'Unknown')}</span></td>
            <td><div class="score-circle ${network.risk_level}">${network.risk_score}</div></td>
            <td>
                <div class="action-group">
                    <button class="btn-detail" data-action="detail" data-index="${index}">Details</button>
                    ${network.risk_level !== 'low' ? `<button class="btn-whitelist" data-action="trust" data-index="${index}">Trust</button>` : ''}
                </div>
            </td>
        </tr>
    `).join('');
}

// One delegated listener for the Details / Trust buttons in the table.
document.addEventListener('click', (e) => {
    const button = e.target.closest('#networksTableBody button[data-action]');
    if (!button) return;
    const network = renderedNetworks[Number(button.dataset.index)];
    if (!network) return;
    if (button.dataset.action === 'detail') showNetworkDetail(network);
    if (button.dataset.action === 'trust') addToWhitelist(network.bssid, network.ssid);
});

function renderSignalBar(dbm) {
    const strength = Math.min(Math.max((dbm + 100) / 70 * 5, 0), 5);
    const bars = [4, 7, 10, 13, 16]; // Heights

    const barsHtml = bars.map((h, i) =>
        `<div class="signal-bar-item ${i < Math.ceil(strength) ? 'active' : ''}" style="height:${h}px;"></div>`
    ).join('');

    return `<div class="signal-bar">
        <div class="signal-bars">${barsHtml}</div>
        <span class="signal-value">${dbm} dBm</span>
    </div>`;
}

function renderAlerts(alerts) {
    const container = document.getElementById('alertsList');
    if (!container) return;

    if (alerts.length === 0) {
        container.innerHTML = '<div class="empty-alerts"><p>No alerts yet. Run a scan to detect potential threats.</p></div>';
        return;
    }

    container.innerHTML = alerts.slice(0, 10).map(alert => `
        <div class="alert-item alert-${alert.risk_level}">
            <div class="alert-indicator"></div>
            <div class="alert-content">
                <div class="alert-header-row">
                    <strong>${escapeHtml(alert.ssid)}</strong>
                    <span class="alert-badge badge-${alert.risk_level}">${alert.risk_level.toUpperCase()}</span>
                </div>
                <p class="alert-message">${escapeHtml((alert.message || '').substring(0, 200))}</p>
                <span class="alert-time">${alert.timestamp}</span>
            </div>
        </div>
    `).join('');
}

/**
 * Tell the user where the results came from. Previously a failed live scan
 * silently fell back to built-in demo data, which looked like a real scan.
 */
function updateModeNotice(mode, note) {
    const notice = document.getElementById('modeNotice');
    if (!notice) return;

    const notices = {
        demo: ['Demo data', `${note || 'No live WiFi scan was possible on this machine.'} These networks are built-in examples, not your surroundings.`],
        simulation: ['Simulated attack', 'These networks were generated by an attack scenario for testing. They are not real.'],
    };

    if (!notices[mode]) {
        notice.style.display = 'none';
        return;
    }
    notice.className = `mode-notice mode-${mode}`;
    document.getElementById('modeNoticeTitle').textContent = notices[mode][0];
    document.getElementById('modeNoticeText').textContent = notices[mode][1];
    notice.style.display = 'flex';
}

function updateThreatBanner(networks) {
    const banner = document.getElementById('threatBanner');
    if (!banner) return;

    // Previously an empty result returned here, leaving the user with an empty
    // table and no explanation. Say clearly that nothing was found and why.
    if (networks.length === 0) {
        banner.className = 'threat-banner threat-warning';
        banner.style.display = 'block';
        document.getElementById('threatIcon').textContent = '📡';
        document.getElementById('threatTitle').textContent = 'No Wi-Fi Networks Detected';
        document.getElementById('threatMessage').textContent =
            'The scan finished but no access points were reported. Check that Wi-Fi is switched on, ' +
            'that a wireless adapter is present and, on Windows 11, that Location access is allowed ' +
            'for desktop apps. Then scan again.';
        return;
    }

    const highRisk = networks.filter(n => n.risk_level === 'high').length;
    const mediumRisk = networks.filter(n => n.risk_level === 'medium').length;

    let level, icon, title, message;

    if (highRisk > 0) {
        level = 'critical';
        icon = '🚨';
        title = `DANGER: ${highRisk} High-Risk Network${highRisk > 1 ? 's' : ''} Detected`;
        message = 'Possible Evil Twin attack in progress. Avoid connecting to flagged networks.';
    } else if (mediumRisk > 0) {
        level = 'warning';
        icon = '⚡';
        title = `CAUTION: ${mediumRisk} Suspicious Network${mediumRisk > 1 ? 's' : ''} Found`;
        message = 'Some networks show suspicious behavior. Exercise caution.';
    } else {
        level = 'safe';
        icon = '✅';
        title = 'Environment Appears Safe';
        message = `All ${networks.length} detected networks show normal behavior.`;
    }

    banner.className = `threat-banner threat-${level}`;
    banner.style.display = 'block';
    document.getElementById('threatIcon').textContent = icon;
    document.getElementById('threatTitle').textContent = title;
    document.getElementById('threatMessage').textContent = message;

    // Update status dot
    const statusDot = document.getElementById('statusDot');
    if (statusDot) {
        statusDot.classList.remove('scanning', 'danger');
        if (level === 'critical') statusDot.classList.add('danger');
    }
}

// ─────────────────────────────────────
// Network Detail Modal
// ─────────────────────────────────────

function showNetworkDetail(network) {
    const modal = document.getElementById('networkModal');
    const modalSSID = document.getElementById('modalSSID');
    const modalRiskBadge = document.getElementById('modalRiskBadge');
    const modalBody = document.getElementById('modalBody');

    modalSSID.textContent = network.ssid;
    modalRiskBadge.innerHTML = `<span class="badge badge-${network.risk_level}">${network.risk_level.toUpperCase()} (${network.risk_score}/100)</span>`;

    let html = `
        <div style="margin-bottom:1.5rem;">
            <h3 style="font-size:0.95rem; color:var(--cyan); margin-bottom:0.75rem;">Network Information</h3>
            <div class="detail-row"><span>SSID</span><span>${escapeHtml(network.ssid)}</span></div>
            <div class="detail-row"><span>BSSID</span><span>${escapeHtml(network.bssid)}</span></div>
            <div class="detail-row"><span>Signal Strength</span><span>${network.signal_strength} dBm</span></div>
            <div class="detail-row"><span>Channel</span><span>${network.channel} (${network.frequency})</span></div>
            <div class="detail-row"><span>Encryption</span><span>${escapeHtml(network.encryption)}</span></div>
            <div class="detail-row"><span>Vendor</span><span>${escapeHtml(network.vendor || 'Unknown')}</span></div>
        </div>
    `;

    if (network.risk_factors && network.risk_factors.length > 0) {
        html += `<h3 style="font-size:0.95rem; color:var(--cyan); margin-bottom:0.75rem;">Risk Factors</h3>`;
        network.risk_factors.forEach(factor => {
            const name = typeof factor === 'object' ? factor.factor : factor;
            const detail = typeof factor === 'object' ? factor.detail : '';
            const severity = typeof factor === 'object' ? factor.severity : 'low';
            html += `
                <div class="risk-factor-item severity-${severity}">
                    <div class="risk-factor-header">
                        <span class="risk-factor-name">${escapeHtml(name)}</span>
                        <span class="badge badge-${severity}">${severity.toUpperCase()}</span>
                    </div>
                    ${detail ? `<p class="risk-factor-detail">${escapeHtml(detail)}</p>` : ''}
                </div>
            `;
        });
    } else {
        html += `<p class="text-muted">No specific risk factors detected for this network.</p>`;
    }

    modalBody.innerHTML = html;
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
}

function closeModal(event) {
    if (event && event.target !== event.currentTarget) return;
    const modal = document.getElementById('networkModal');
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = '';
    }
}

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});

// ─────────────────────────────────────
// Filtering
// ─────────────────────────────────────

function filterNetworks(level) {
    currentFilter = level;

    // Update active button
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === level);
    });

    renderNetworks(currentNetworks);
}

// ─────────────────────────────────────
// Whitelist
// ─────────────────────────────────────

async function addToWhitelist(bssid, ssid) {
    if (!confirm(`Add "${ssid}" (${bssid}) to trusted networks?`)) return;

    try {
        const response = await fetch('/api/whitelist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bssid, ssid })
        });

        const data = await response.json();
        if (data.status === 'ok') {
            showSuccess(`"${ssid}" added to trusted networks.`);
            // Re-scan to update risk scores
            await loadNetworks();
        } else {
            showError(data.message || 'Failed to add to whitelist');
        }
    } catch (error) {
        showError('Failed to update whitelist');
    }
}

// ─────────────────────────────────────
// Notifications
// ─────────────────────────────────────

function showSuccess(message) {
    showNotification(message, 'success');
}

function showError(message) {
    showNotification(message, 'error');
}

function showNotification(message, type) {
    // Remove existing notifications
    document.querySelectorAll('.notification').forEach(n => n.remove());

    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()" style="background:none;border:none;color:inherit;font-size:1.2rem;cursor:pointer;margin-left:1rem;">&times;</button>
    `;

    // Styles
    Object.assign(notification.style, {
        position: 'fixed',
        top: '80px',
        right: '20px',
        padding: '1rem 1.5rem',
        borderRadius: '10px',
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
        zIndex: '9999',
        fontFamily: 'Outfit, sans-serif',
        fontSize: '0.9rem',
        fontWeight: '500',
        animation: 'slideIn 0.3s ease',
        maxWidth: '450px',
        boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
    });

    if (type === 'success') {
        notification.style.background = 'rgba(0, 230, 118, 0.15)';
        notification.style.border = '1px solid rgba(0, 230, 118, 0.3)';
        notification.style.color = '#00e676';
    } else {
        notification.style.background = 'rgba(255, 59, 92, 0.15)';
        notification.style.border = '1px solid rgba(255, 59, 92, 0.3)';
        notification.style.color = '#ff3b5c';
    }

    document.body.appendChild(notification);

    // Auto remove after 5s
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(100%)';
            notification.style.transition = 'all 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }
    }, 5000);
}

// Add slideIn animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { opacity: 0; transform: translateX(100%); }
        to { opacity: 1; transform: translateX(0); }
    }
`;
document.head.appendChild(style);

// ─────────────────────────────────────
// Helpers
// ─────────────────────────────────────

function escapeHtml(text) {
    if (!text) return '';
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

function updateElement(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

// ─────────────────────────────────────
// Simulation Mode
// ─────────────────────────────────────

let simPanelOpen = false;
let scenariosLoaded = false;

function toggleSimPanel() {
    simPanelOpen = !simPanelOpen;
    const dropdown = document.getElementById('simDropdown');
    
    if (simPanelOpen) {
        dropdown.style.display = 'block';
        if (!scenariosLoaded) loadScenarios();
    } else {
        dropdown.style.display = 'none';
    }
}

async function loadScenarios() {
    try {
        const response = await fetch('/api/simulate/scenarios');
        const data = await response.json();
        const container = document.getElementById('simScenarios');
        
        container.innerHTML = data.scenarios.map(s => `
            <div class="sim-card" onclick="runSimulation('${s.id}')">
                <div class="sim-card-header">
                    <span class="sim-card-name">${escapeHtml(s.name)}</span>
                    <span class="sim-card-difficulty ${s.difficulty}">${s.difficulty}</span>
                </div>
                <p class="sim-card-desc">${escapeHtml(s.description)}</p>
                <div class="sim-card-meta">
                    <span>📡 ${s.networks} networks</span>
                    <span class="threats">⚠️ ${s.threats} threats</span>
                </div>
            </div>
        `).join('');
        
        scenariosLoaded = true;
    } catch (error) {
        console.error('Failed to load scenarios:', error);
        document.getElementById('simScenarios').innerHTML = 
            '<div class="sim-loading">Failed to load scenarios.</div>';
    }
}

async function runSimulation(scenarioId) {
    if (isScanning) return;

    const btn = document.getElementById('btnScan');
    const btnText = document.getElementById('btnScanText');
    const scanAnim = document.getElementById('scanAnimation');
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    const scanStatusText = document.getElementById('scanStatusText');

    // Close sim panel
    document.getElementById('simDropdown').style.display = 'none';
    simPanelOpen = false;

    // Update UI
    isScanning = true;
    btn.classList.add('scanning');
    btnText.textContent = 'Simulating...';
    scanAnim.style.display = 'flex';
    statusDot.classList.add('scanning');
    statusText.textContent = 'Simulating...';
    if (scanStatusText) scanStatusText.textContent = 'Generating simulated attack scenario...';

    try {
        const response = await fetch(`/api/simulate/${scenarioId}`, { method: 'POST' });
        const data = await response.json();

        if (data.status === 'ok') {
            pollForResults();
        } else {
            showError(data.message || 'Simulation failed');
            resetScanUI();
        }
    } catch (error) {
        console.error('Simulation error:', error);
        showError('Failed to start simulation');
        resetScanUI();
    }
}

// Close sim dropdown when clicking outside
document.addEventListener('click', (e) => {
    if (simPanelOpen && !e.target.closest('.sim-panel')) {
        document.getElementById('simDropdown').style.display = 'none';
        simPanelOpen = false;
    }
});
