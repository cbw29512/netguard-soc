const socket = io();

// Store current devices for modal access
let currentDevices = [];
let selectedDevice = null;

// ============ CONNECTION HANDLING ============
socket.on('connect', () => {
    console.log('🛡️ Connected to NetGuard SOC v3.2');
});

socket.on('disconnect', () => {
    console.log('⚠️ Disconnected from NetGuard SOC');
});

socket.on('connected', (data) => {
    console.log('Server:', data);
});

// ============ AI THOUGHTS MARQUEE ============
socket.on('update_thoughts', (data) => {
    const thoughts = data.thoughts || [];
    const marquee = document.getElementById('aiMarquee');
    
    if (thoughts.length === 0) {
        marquee.innerHTML = '<span class="thought">🛡️ AI SECURITY GUARD MONITORING...</span>';
        return;
    }
    
    const items = thoughts.map(t => {
        const levelClass = t.level || 'info';
        const icon = t.level === 'alert' ? '🚨' : 
                     t.level === 'warning' ? '⚠️' : 
                     t.level === 'system' ? '🖥️' :
                     t.level === 'info' ? '✓' : '🤖';
        const hasIcon = /^[\u{1F300}-\u{1F9FF}]/u.test(t.thought);
        return `<span class="thought ${levelClass}">${hasIcon ? '' : icon + ' '}${t.thought}</span>`;
    }).join('');
    
    marquee.innerHTML = items + items;
});

// ============ DEVICE GRID ============
socket.on('update_devices', (data) => {
    const devices = data.devices || [];
    currentDevices = devices; // Store for modal access
    const grid = document.getElementById('deviceGrid');
    
    // Update header stats
    document.getElementById('deviceCount').textContent = data.count || 0;
    const alertCount = devices.reduce((sum, d) => sum + (d.alert_count || 0), 0);
    document.getElementById('alertCount').textContent = alertCount;
    
    const alertStat = document.getElementById('alertStat');
    alertStat.className = 'stat-box' + (alertCount > 0 ? ' alert' : '');
    
    if (devices.length === 0) {
        if (data.error) {
            grid.innerHTML = `
                <div class="loading-card">
                    <p style="color: var(--accent-red);">⚠️ ${data.error}</p>
                </div>`;
        } else {
            grid.innerHTML = `
                <div class="loading-card">
                    <p>📡 No active devices detected</p>
                </div>`;
        }
        return;
    }
    
    grid.innerHTML = devices.map((device, idx) => {
        const displayName = device.friendly_name || device.hostname || 'Unknown Device';
        const showHostname = device.friendly_name && device.hostname && 
                            device.friendly_name !== device.hostname;
        
        let cardClass = 'device-card';
        cardClass += device.online ? ' online' : ' offline';
        if (device.alert_count > 0) {
            const hasHighAlert = device.alerts.some(a => a.severity === 'medium' || a.severity === 'high');
            cardClass += hasHighAlert ? ' alert' : ' warning';
        }
        
        let connBadge = '';
        if (device.conn_type === 'Ethernet') {
            connBadge = '<span class="badge badge-lan">🔌 Ethernet</span>';
        } else if (device.conn_type.startsWith('WiFi')) {
            const band = device.wifi_band || '';
            const bandClass = band.includes('5') ? 'badge-wifi-5g' : 
                             band.includes('6') ? 'badge-wifi-6g' : 'badge-wifi';
            connBadge = `<span class="badge ${bandClass}">📶 ${device.conn_type}</span>`;
        } else {
            connBadge = '<span class="badge badge-unknown-conn">❓ Unknown</span>';
        }
        
        let alertsHtml = '';
        if (device.alerts && device.alerts.length > 0) {
            alertsHtml = `
                <div class="device-alerts">
                    ${device.alerts.map(a => `
                        <div class="alert-item ${a.severity}">
                            <span>${a.type === 'unknown' ? '❓' : a.type === 'drift' ? '↔️' : '🔀'}</span>
                            <span>${a.message}</span>
                        </div>
                    `).join('')}
                </div>`;
        }
        
        const firstSeenRow = device.first_seen ? `
            <div class="info-row">
                <span class="info-label">First Seen</span>
                <span class="info-value">${device.first_seen}</span>
            </div>` : '';
        
        return `
            <div class="${cardClass}" onclick="openDeviceModal(${idx})" data-device-idx="${idx}">
                <div class="device-header">
                    <div>
                        <div class="device-name">${escapeHtml(displayName)}</div>
                        ${showHostname ? `<div class="device-hostname">${escapeHtml(device.hostname)}</div>` : ''}
                    </div>
                    <div class="device-badge">
                        <span class="badge ${device.online ? 'badge-online' : 'badge-offline'}">
                            ${device.online ? '● ONLINE' : '○ OFFLINE'}
                        </span>
                    </div>
                </div>
                <div class="device-conn-type">
                    ${connBadge}
                    <span class="badge ${device.known ? 'badge-known' : 'badge-unknown'}">
                        ${device.known ? '✓ KNOWN' : '? UNKNOWN'}
                    </span>
                </div>
                <div class="device-info">
                    <div class="info-row">
                        <span class="info-label">IP Address</span>
                        <span class="info-value mono">${device.ip}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Lease Expires</span>
                        <span class="info-value">${device.lease_expiry}</span>
                    </div>
                    <div class="info-row full">
                        <span class="info-label">MAC Address</span>
                        <span class="info-value mono">${device.mac}</span>
                    </div>
                    ${firstSeenRow}
                </div>
                ${alertsHtml}
            </div>
        `;
    }).join('');
    
    // Update modal if open
    if (selectedDevice !== null) {
        const updated = currentDevices.find(d => d.mac === selectedDevice.mac);
        if (updated) {
            selectedDevice = updated;
            renderModalBody(updated);
        }
    }
});

// ============ DEVICE MODAL ============
function openDeviceModal(idx) {
    const device = currentDevices[idx];
    if (!device) return;
    
    selectedDevice = device;
    
    document.getElementById('modalDeviceName').textContent = 
        device.friendly_name || device.hostname || 'Unknown Device';
    document.getElementById('modalDeviceIP').textContent = 
        `${device.ip} • ${device.mac}`;
    
    renderModalBody(device);
    document.getElementById('deviceModalOverlay').classList.add('active');
    document.body.style.overflow = 'hidden';
}

function renderModalBody(device) {
    const modal = document.getElementById('modalBody');
    
    const statusClass = device.online ? 'online' : 'offline';
    const statusText = device.online ? '● ONLINE' : '○ OFFLINE';
    
    let alertsHtml = '<p style="color:var(--text-muted);">No active alerts</p>';
    if (device.alerts && device.alerts.length > 0) {
        alertsHtml = `<div class="modal-alerts">
            ${device.alerts.map(a => `
                <div class="modal-alert ${a.severity}">
                    <strong>${a.type.toUpperCase()}</strong>: ${a.message}
                </div>
            `).join('')}
        </div>`;
    }
    
    modal.innerHTML = `
        <div class="modal-section">
            <div class="modal-section-title">Device Status</div>
            <div class="modal-grid">
                <div class="modal-stat">
                    <div class="modal-stat-label">Status</div>
                    <div class="modal-stat-value ${statusClass}">${statusText}</div>
                </div>
                <div class="modal-stat">
                    <div class="modal-stat-label">Connection</div>
                    <div class="modal-stat-value">${device.conn_type || 'Unknown'}</div>
                </div>
                <div class="modal-stat">
                    <div class="modal-stat-label">WiFi Band</div>
                    <div class="modal-stat-value">${device.wifi_band || 'N/A'}</div>
                </div>
                <div class="modal-stat">
                    <div class="modal-stat-label">Known Device</div>
                    <div class="modal-stat-value ${device.known ? 'online' : 'warning'}">${device.known ? 'YES' : 'NO'}</div>
                </div>
            </div>
        </div>
        
        <div class="modal-section">
            <div class="modal-section-title">Network Details</div>
            <div class="modal-grid">
                <div class="modal-stat">
                    <div class="modal-stat-label">IP Address</div>
                    <div class="modal-stat-value mono">${device.ip}</div>
                </div>
                <div class="modal-stat">
                    <div class="modal-stat-label">MAC Address</div>
                    <div class="modal-stat-value mono">${device.mac}</div>
                </div>
                <div class="modal-stat">
                    <div class="modal-stat-label">Hostname</div>
                    <div class="modal-stat-value">${device.hostname || 'Unknown'}</div>
                </div>
                <div class="modal-stat">
                    <div class="modal-stat-label">Friendly Name</div>
                    <div class="modal-stat-value">${device.friendly_name || 'Not Set'}</div>
                </div>
            </div>
        </div>
        
        <div class="modal-section">
            <div class="modal-section-title">DHCP Lease</div>
            <div class="modal-grid">
                <div class="modal-stat">
                    <div class="modal-stat-label">Lease Expires</div>
                    <div class="modal-stat-value">${device.lease_expiry}</div>
                </div>
                <div class="modal-stat">
                    <div class="modal-stat-label">Lease Seconds</div>
                    <div class="modal-stat-value mono">${device.lease_seconds || 0}s</div>
                </div>
                <div class="modal-stat">
                    <div class="modal-stat-label">First Seen</div>
                    <div class="modal-stat-value">${device.first_seen || 'Unknown'}</div>
                </div>
                <div class="modal-stat">
                    <div class="modal-stat-label">Alert Count</div>
                    <div class="modal-stat-value ${device.alert_count > 0 ? 'warning' : ''}">${device.alert_count}</div>
                </div>
            </div>
        </div>
        
        <div class="modal-section">
            <div class="modal-section-title">Security Alerts</div>
            ${alertsHtml}
        </div>
    `;
}

function closeDeviceModal() {
    selectedDevice = null;
    document.getElementById('deviceModalOverlay').classList.remove('active');
    document.body.style.overflow = '';
}

// Modal close handlers
document.getElementById('modalClose').addEventListener('click', closeDeviceModal);
document.getElementById('deviceModalOverlay').addEventListener('click', (e) => {
    if (e.target === document.getElementById('deviceModalOverlay')) {
        closeDeviceModal();
    }
});
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDeviceModal();
});

// ============ ROUTER STATUS ============
socket.on('update_router', (data) => {
    // Parse uptime_raw: " 10:44:01 up 1 day, 18:56, load..." -> "1d 18h 56m"
    let uptime = '--';
    const raw = data.uptime_raw || '';
    const match = raw.match(/up\s+(?:(\d+)\s*days?,?\s*)?(?:(\d+):(\d+))?/);
    if (match) {
        const days = match[1] ? parseInt(match[1]) : 0;
        const hours = match[2] ? parseInt(match[2]) : 0;
        const mins = match[3] ? parseInt(match[3]) : 0;
        let parts = [];
        if (days > 0) parts.push(`${days}d`);
        if (hours > 0) parts.push(`${hours}h`);
        if (mins > 0) parts.push(`${mins}m`);
        uptime = parts.join(' ') || '0m';
    }
    document.getElementById('routerUptime').textContent = uptime;
    
    const memPct = data.mem_used_pct || 0;
    document.getElementById('memUsage').textContent = `${memPct}%`;
    
    const memoryStat = document.getElementById('memoryStat');
    memoryStat.className = 'stat-box' + (memPct > 80 ? ' alert' : memPct > 60 ? ' warning' : '');
    
    // Enhanced risk display: "LOW 0/100"
    const riskEl = document.getElementById('riskScore');
    if (riskEl) {
        const level = data.risk_level || 'LOW';
        riskEl.textContent = `${level} ${data.risk_score || 0}/100`;
        const riskStat = document.getElementById('riskStat');
        if (riskStat) {
            riskStat.className = 'stat-box' + (level === 'HIGH' ? ' alert' : level === 'MEDIUM' ? ' warning' : '');
        }
    }
});

// ============ WIFI BANDS ============
socket.on('update_wifi', (data) => {
    const bands = data.bands || [];
    
    bands.forEach(band => {
        const card = document.querySelector(`.band-card[data-band="${band.interface}"]`);
        if (!card) return;
        
        const utilEl = card.querySelector('.band-util');
        const labelEl = card.querySelector('.band-label');
        const countEl = card.querySelector('.band-count');
        
        if (labelEl) labelEl.textContent = band.label;
        if (utilEl) utilEl.textContent = `${band.utilization}% util`;
        if (countEl) countEl.textContent = `${band.assoc_count} devices`;
        
        card.classList.toggle('active', band.assoc_count > 0);
        card.classList.toggle('busy', band.utilization > 50);
    });
});

// ============ SERVICES FOOTER ============
socket.on('update_services', (data) => {
    const services = data.services || [];
    const grid = document.getElementById('serviceGrid');
    
    grid.innerHTML = services.map(svc => {
        let statusClass = 'inactive';
        if (svc.status === 'active' || svc.status === 'activating') {
            statusClass = 'ok';
        } else if (svc.status === 'failed') {
            statusClass = 'error';
        }
        
        return `
            <div class="service-pill ${statusClass}" title="${svc.name}: ${svc.status}">
                <span class="dot"></span>
                <span>${svc.display}</span>
            </div>
        `;
    }).join('');
    
    const hasErrors = services.some(s => s.status === 'failed');
    const pulseDot = document.querySelector('.pulse-dot');
    if (pulseDot) {
        pulseDot.style.background = hasErrors ? 'var(--accent-red)' : 'var(--accent-green)';
    }
});

// ============ STATUS UPDATE ============
socket.on('update_status', (data) => {
    const riskEl = document.getElementById('riskScore');
    if (riskEl && data.risk_score !== undefined) {
        riskEl.textContent = `${data.risk_score}/100`;
    }
});

// ============ UTILITY FUNCTIONS ============
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('🛡️ NetGuard SOC Dashboard v3.2.3 loaded');
});
