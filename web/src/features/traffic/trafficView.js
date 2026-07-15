import { state } from '../../app/state.js';
import { escapeHtml, formatBytes, formatNumber } from '../../lib/format.js';
import { renderTrafficCharts } from '../../components/ui/chart.js';
import * as api from '../../lib/api.js';
import { trafficRangeConfig } from '../../lib/timeRanges.js';
import { deviceIPCell, deviceHref } from '../../lib/deviceLinks.js';
import { renderFlowExplorer } from './trafficFlowExplorer.js';

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
    
    api.fetchStatsTopDevices(range)
        .then(devices => {
            const sortedDevices = [...devices].sort((a, b) => b.bytes - a.bytes);
            if (sortedDevices.length === 0) {
                topTalkerSignal.textContent = "No local device traffic in the active window.";
                return;
            }
            const totalBytes = sortedDevices.reduce((sum, item) => sum + item.bytes, 0) || 1;
            topTalkerSignal.innerHTML = sortedDevices.map(item => {
                const pct = (item.bytes / totalBytes) * 100;
                return `<div class="signal-row">
                    <span class="signal-key">${deviceIPCell(item.key)}</span>
                    <span class="signal-value">${pct.toFixed(1)}%</span>
                    <div class="signal-bar"><span style="width:${Math.max(pct, 2)}%"></span></div>
                </div>`;
            }).join("");
        })
        .catch(() => {
            topTalkerSignal.textContent = "Local device share unavailable.";
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

    Promise.all([
        api.fetchTopTalkers("protocols", range, "6").catch(() => []),
        api.fetchTopTalkers("ports", range, "6").catch(() => [])
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
            <a class="signal-key ip-link" href="#/devices/subnet/${encodeURIComponent(subnet)}">${subnet}</a>
            <span class="signal-value">${val.count} devices · ${val.risk} risky</span>
        </div>
    `).join("");
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
                            <span class="risk-device-ip">${deviceIPCell(dev.ip)}</span>
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
            const href = deviceHref(ip);
            if (href) window.location.hash = href;
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
        const isIP = state.activeTab === "devices" || state.activeTab === "sources" || state.activeTab === "destinations";
        const keyHtml = isIP ? deviceIPCell(item.key) : escapeHtml(item.key);
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
    renderTrafficCharts(renderNetworkSignals);
    renderThreatRisk();
    renderTopTalkers();
    renderFlowExplorer();
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


    const explorerSearch = document.getElementById("flow-explorer-search");
    const explorerProtocol = document.getElementById("flow-explorer-protocol");
    const explorerPort = document.getElementById("flow-explorer-port");
    const explorerButton = document.getElementById("btn-flow-explorer-search");
    const applyExplorerFilters = () => {
        state.trafficRecordFilters = {
            q: explorerSearch ? explorerSearch.value.trim() : "",
            protocol: explorerProtocol ? explorerProtocol.value.trim() : "",
            dstPort: explorerPort ? explorerPort.value.trim() : ""
        };
        if (onReload) onReload(true);
    };
    if (explorerButton) explorerButton.addEventListener("click", applyExplorerFilters);
    [explorerSearch, explorerProtocol, explorerPort].forEach(input => {
        if (!input) return;
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") applyExplorerFilters();
        });
    });

    const explorerCollector = document.getElementById("flow-explorer-collector");
    if (explorerCollector) {
        explorerCollector.addEventListener("change", () => {
            renderFlowExplorer();
        });
    }

    document.querySelectorAll("[data-flow-sort]").forEach(btn => {
        const applySort = () => {
            const key = btn.getAttribute("data-flow-sort");
            const current = state.trafficRecordSort || { key: "timestamp", direction: "desc" };
            const nextDirection = current.key === key && current.direction === "desc" ? "asc" : "desc";
            state.trafficRecordSort = { key, direction: nextDirection };
            renderFlowExplorer();
        };
        btn.addEventListener("click", applySort);
        btn.addEventListener("keydown", (e) => {
            if (e.key !== "Enter" && e.key !== " ") return;
            e.preventDefault();
            applySort();
        });
    });
}
