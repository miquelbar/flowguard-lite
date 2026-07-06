import { state } from '../state.js';
import { formatBytes, formatNumber, formatTime } from '../utils/format.js';
import { renderTrafficChart } from '../components/chart.js';
import * as api from '../api.js';

export function trafficRangeConfig() {
    const end = new Date();
    const configs = {
        "1h": { start: new Date(end.getTime() - 60 * 60 * 1000), bucket: 60 },
        "6h": { start: new Date(end.getTime() - 6 * 60 * 60 * 1000), bucket: 300 },
        "24h": { start: new Date(end.getTime() - 24 * 60 * 60 * 1000), bucket: 900 },
        "7d": { start: new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000), bucket: 3600 }
    };
    return { ...configs[state.activeTrafficRange], end };
}

export function updateDashboardHeroStats() {
    const valTotalVolume = document.getElementById("val-total-volume");
    const valDevicesCount = document.getElementById("val-devices-count");
    const valActiveAlerts = document.getElementById("val-active-alerts");
    const valMaxRisk = document.getElementById("val-max-risk");

    let totalBytes = 0;
    if (state.trafficSeriesData && state.trafficSeriesData.length > 0) {
        state.trafficSeriesData.forEach(item => {
            totalBytes += Number(item.bytes || 0);
        });
    }
    if (valTotalVolume) {
        valTotalVolume.textContent = formatBytes(totalBytes);
    }

    if (valDevicesCount) {
        valDevicesCount.textContent = state.devicesData ? formatNumber(state.devicesData.length) : "0";
    }

    if (valActiveAlerts) {
        const activeCount = (state.anomaliesData || []).filter(a => a.status === "active").length;
        valActiveAlerts.textContent = formatNumber(activeCount);
    }

    if (valMaxRisk) {
        let maxScore = 0;
        if (state.riskDevicesData && state.riskDevicesData.length > 0) {
            state.riskDevicesData.forEach(d => {
                if (d.risk_score > maxScore) {
                    maxScore = d.risk_score;
                }
            });
        }
        valMaxRisk.textContent = formatNumber(maxScore);
        
        valMaxRisk.className = "stat-value";
        if (maxScore >= 70) {
            valMaxRisk.classList.add("text-danger");
        } else if (maxScore >= 30) {
            valMaxRisk.classList.add("text-warning");
        }
    }
}

export function renderNetworkSignals() {
    renderTopTalkerSignal();
    renderPortDistributionSignal();
    renderSubnetSummarySignal();
}

function renderTopTalkerSignal() {
    const topTalkerSignal = document.getElementById("top-talker-signal");
    if (!topTalkerSignal) return;
    const range = trafficRangeConfig();
    
    api.fetchTopTalkers("sources", range)
        .then(sources => {
            const sortedSources = [...sources].sort((a, b) => b.bytes - a.bytes);
            if (sortedSources.length === 0) {
                topTalkerSignal.textContent = "No top talker data in the active window.";
                return;
            }
            const totalBytes = sortedSources.reduce((sum, item) => sum + item.bytes, 0) || 1;
            topTalkerSignal.innerHTML = sortedSources.map(item => {
                const pct = (item.bytes / totalBytes) * 100;
                return `<div class="signal-row">
                    <span class="signal-key">${item.key}</span>
                    <span class="signal-value">${pct.toFixed(1)}%</span>
                    <div class="signal-bar"><span style="width:${Math.max(pct, 2)}%"></span></div>
                </div>`;
            }).join("");
        })
        .catch(() => {
            topTalkerSignal.textContent = "Top talker share unavailable.";
        });
}

function protocolName(protocol) {
    const labels = {
        "1": "ICMP",
        "6": "TCP",
        "17": "UDP",
        "47": "GRE",
        "50": "ESP",
        "58": "ICMPv6"
    };
    return labels[String(protocol)] || `IP ${protocol}`;
}

function renderPortDistributionSignal() {
    const portDistributionSignal = document.getElementById("port-distribution-signal");
    if (!portDistributionSignal) return;
    const range = trafficRangeConfig();
    const params = new URLSearchParams({
        limit: "6",
        start: range.start.toISOString(),
        end: range.end.toISOString()
    });

    Promise.all([
        fetch(`/api/top/protocols?${params.toString()}`).then(resp => resp.ok ? resp.json() : []),
        fetch(`/api/top/ports?${params.toString()}`).then(resp => resp.ok ? resp.json() : [])
    ])
        .then(([protocols, ports]) => {
            if ((!protocols || protocols.length === 0) && (!ports || ports.length === 0)) {
                portDistributionSignal.textContent = "No protocol or destination port data in the active window.";
                return;
            }

            const protocolTotal = protocols.reduce((sum, item) => sum + item.bytes, 0) || 1;
            const portTotal = ports.reduce((sum, item) => sum + item.bytes, 0) || 1;
            const protocolRows = protocols.slice(0, 2).map(item => {
                const pct = (item.bytes / protocolTotal) * 100;
                return `<div class="signal-row">
                    <span class="signal-key">${protocolName(item.key)}</span>
                    <span class="signal-value">${pct.toFixed(0)}%</span>
                    <div class="signal-bar signal-bar-protocol"><span style="width:${Math.max(pct, 2)}%"></span></div>
                </div>`;
            }).join("");
            const portRows = ports.slice(0, 3).map(item => {
                const pct = (item.bytes / portTotal) * 100;
                return `<div class="signal-row">
                    <span class="signal-key">:${item.key}</span>
                    <span class="signal-value">${formatBytes(item.bytes)}</span>
                    <div class="signal-bar"><span style="width:${Math.max(pct, 2)}%"></span></div>
                </div>`;
            }).join("");

            portDistributionSignal.innerHTML = `
                ${protocolRows ? `<div class="signal-section-label">Protocols</div>${protocolRows}` : ""}
                ${portRows ? `<div class="signal-section-label">Destination ports</div>${portRows}` : ""}
            `;
        })
        .catch(() => {
            portDistributionSignal.textContent = "Protocol and port distribution unavailable.";
        });
}

function subnetLabelFor(ip) {
    const parts = ip.split(".");
    if (parts.length < 3) return "Unknown";
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function renderSubnetSummarySignal() {
    const subnetSummarySignal = document.getElementById("subnet-summary-signal");
    if (!subnetSummarySignal) return;
    const summary = new Map();
    state.devicesData.forEach(dev => {
        const subnet = subnetLabelFor(dev.ip);
        if (!summary.has(subnet)) summary.set(subnet, { count: 0, risk: 0 });
        summary.get(subnet).count += 1;
    });
    state.riskDevicesData.forEach(dev => {
        const subnet = subnetLabelFor(dev.ip);
        if (!summary.has(subnet)) summary.set(subnet, { count: 0, risk: 0 });
        summary.get(subnet).risk += 1;
    });
    if (summary.size === 0) {
        subnetSummarySignal.textContent = "No discovered local subnets yet.";
        return;
    }
    subnetSummarySignal.innerHTML = [...summary.entries()].sort().slice(0, 4).map(([subnet, val]) => `
        <div class="subnet-row">
            <span class="signal-key">${subnet}</span>
            <span class="signal-value">${val.count} devices · ${val.risk} risky</span>
        </div>
    `).join("");
}

export function renderExporters() {
    const tblExporters = document.getElementById("tbl-exporters").querySelector("tbody");
    if (!tblExporters) return;

    if (!state.exportersData || state.exportersData.length === 0) {
        tblExporters.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No active exporters observed.</td></tr>`;
        return;
    }

    tblExporters.innerHTML = state.exportersData.map(exp => `
        <tr>
            <td>${exp.ip}</td>
            <td>${formatTime(exp.last_seen)}</td>
            <td class="text-right">${formatNumber(exp.packet_count)}</td>
        </tr>
    `).join('');
}

export function renderThreatRisk() {
    const tblThreatRisk = document.getElementById("tbl-threat-risk").querySelector("tbody");
    if (!tblThreatRisk) return;

    if (!state.riskDevicesData || state.riskDevicesData.length === 0) {
        tblThreatRisk.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No elevated-risk devices.</td></tr>`;
        return;
    }

    tblThreatRisk.innerHTML = state.riskDevicesData.map(dev => {
        const badgeClass = dev.risk_level === "high" ? "risk-badge-high" : (dev.risk_level === "medium" ? "risk-badge-medium" : "risk-badge-low");
        
        let summaryText = "";
        if (dev.breakdown) {
            const parts = [];
            const highCount = (dev.breakdown.alert_breakdown || []).filter(c => c.severity === "high").length;
            const medCount = (dev.breakdown.alert_breakdown || []).filter(c => c.severity === "medium").length;
            const lowCount = (dev.breakdown.alert_breakdown || []).filter(c => c.severity === "low").length;
            
            if (highCount > 0) parts.push(`${highCount} high`);
            if (medCount > 0) parts.push(`${medCount} med`);
            if (lowCount > 0) parts.push(`${lowCount} low`);
            
            let contributors = parts.join(", ");
            if (contributors) {
                summaryText = `${contributors}`;
            }
            if (dev.breakdown.correlation_boost > 0) {
                if (summaryText) {
                    summaryText += ` + boost (+${dev.breakdown.correlation_boost} pts)`;
                } else {
                    summaryText = `Correlation boost (+${dev.breakdown.correlation_boost} pts)`;
                }
            }
        }

        return `
            <tr style="cursor: pointer;" class="threat-device-row" data-ip="${dev.ip}">
                <td>
                    <div class="risk-device-cell" style="display: flex; flex-direction: column; gap: 0.15rem;">
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            <span class="risk-device-ip"><a href="#/devices/${dev.ip}" class="ip-link">${dev.ip}</a></span>
                            ${dev.label ? `<span class="badge badge-label risk-device-label">${dev.label}</span>` : ''}
                        </div>
                        ${summaryText ? `<span class="text-muted" style="font-size: 0.72rem; line-height: 1.2;">Contributors: ${summaryText}</span>` : ''}
                    </div>
                </td>
                <td><span class="risk-badge ${badgeClass} risk-score-badge">${dev.risk_score}</span></td>
                <td class="text-right text-muted" style="text-transform: capitalize;">${dev.risk_level}</td>
            </tr>
        `;
    }).join('');

    tblThreatRisk.querySelectorAll(".threat-device-row").forEach(row => {
        row.addEventListener("click", (e) => {
            if (e.target.tagName === "A") return;
            const ip = row.getAttribute("data-ip");
            window.location.hash = `#/devices/${ip}`;
        });
    });
}

export function renderTopTalkers() {
    const tblTopTalkers = document.getElementById("tbl-top-talkers").querySelector("tbody");
    const inputSearch = document.getElementById("input-search");
    if (!tblTopTalkers) return;

    const query = inputSearch ? inputSearch.value.trim().toLowerCase() : "";
    const filtered = (state.talkersData || []).filter(item => item.key.toLowerCase().includes(query));

    if (filtered.length === 0) {
        tblTopTalkers.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No records match the active filters.</td></tr>`;
        return;
    }

    const maxBytes = Math.max(...filtered.map(i => i.bytes), 1);

    tblTopTalkers.innerHTML = filtered.map(item => {
        const percentage = (item.bytes / maxBytes) * 100;
        const isIP = state.activeTab === "sources" || state.activeTab === "destinations";
        const keyHtml = isIP ? `<a href="#/devices/${item.key}" class="ip-link">${item.key}</a>` : item.key;
        return `
            <tr>
                <td class="font-semibold">${keyHtml}</td>
                <td class="text-right">${formatNumber(item.flows)}</td>
                <td class="text-right">${formatNumber(item.packets)}</td>
                <td class="text-right">${formatBytes(item.bytes)}</td>
                <td class="width-progress">
                    <div class="progress-track" title="${percentage.toFixed(1)}%">
                        <div class="progress-bar" style="width: ${percentage}%"></div>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

export function renderTrafficView() {
    renderTrafficChart(renderNetworkSignals);
    renderExporters();
    renderThreatRisk();
    renderTopTalkers();
    updateDashboardHeroStats();
}

export function bindTrafficEvents(onReload) {
    const inputSearch = document.getElementById("input-search");
    if (inputSearch) {
        inputSearch.addEventListener("input", () => {
            renderTopTalkers();
        });
    }

    // Bind talkers metric/sources tab switchers
    const talkersTabs = document.querySelectorAll(".talkers-tabs-nav .tab-btn");
    talkersTabs.forEach(btn => {
        btn.addEventListener("click", (e) => {
            talkersTabs.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            state.activeTab = e.target.getAttribute("data-tab");
            if (onReload) onReload();
        });
    });

    // Bind traffic metric buttons (Bytes/Packets/Flows)
    const trafficMetricButtons = document.querySelectorAll(".traffic-metric-btn");
    trafficMetricButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            trafficMetricButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            state.activeTrafficMetric = e.target.getAttribute("data-metric");
            renderTrafficView();
        });
    });

    // Bind traffic range buttons (1h/6h/24h/7d)
    const trafficRangeButtons = document.querySelectorAll(".traffic-range-btn");
    trafficRangeButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            trafficRangeButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            state.activeTrafficRange = e.target.getAttribute("data-range");
            if (onReload) onReload();
        });
    });
}
