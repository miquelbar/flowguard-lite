import { state } from '../state.js';
import { formatBytes, formatNumber, formatTime, formatShortTime, escapeHtml } from '../utils/format.js';
import * as api from '../api.js';
import { trafficRangeConfig } from '../utils/timeRanges.js';
import { isKnownDeviceIP } from '../utils/deviceLinks.js';

export function renderDevices() {
    const tblDevices = document.getElementById("tbl-devices").querySelector("tbody");
    const inputDeviceSearch = document.getElementById("input-device-search");
    const selectDeviceSubnet = document.getElementById("select-device-subnet");
    if (!tblDevices) return;

    renderDeviceSubnetOptions(selectDeviceSubnet);

    const query = inputDeviceSearch ? inputDeviceSearch.value.trim().toLowerCase() : "";
    const selectedSubnet = state.selectedDeviceSubnet || "";
    const filtered = (state.devicesData || []).filter(dev => {
        const subnet = subnetLabelForDevice(dev.ip);
        const subnetMatch = !selectedSubnet || subnet === selectedSubnet;
        const searchMatch = dev.ip.toLowerCase().includes(query) ||
               (dev.hostname && dev.hostname.toLowerCase().includes(query)) ||
               (dev.label && dev.label.toLowerCase().includes(query));
        return subnetMatch && searchMatch;
    });

    if (filtered.length === 0) {
        tblDevices.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No devices match active search filters.</td></tr>`;
        return;
    }

    tblDevices.innerHTML = filtered.map(dev => {
        const isSelected = state.selectedDeviceIP === dev.ip;
        return `
            <tr data-ip="${dev.ip}" class="${isSelected ? 'selected' : ''}">
                <td class="font-semibold"><a href="#/devices/${dev.ip}" class="ip-link">${dev.ip}</a></td>
                <td class="text-muted">${dev.hostname || "<i>Unresolved</i>"}</td>
                <td>${dev.label ? `<span class="badge badge-label">${dev.label}</span>` : '<span class="text-muted">-</span>'}</td>
                <td class="text-center">
                    <button class="btn-secondary btn-select-device" data-ip="${dev.ip}">Select</button>
                </td>
            </tr>
        `;
    }).join('');

    tblDevices.querySelectorAll("tr").forEach(row => {
        row.addEventListener("click", (e) => {
            if (e.target.tagName === "BUTTON" || e.target.tagName === "A") return;
            const ip = row.getAttribute("data-ip");
            window.location.hash = `#/devices/${ip}`;
        });
    });

    tblDevices.querySelectorAll(".btn-select-device").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const ip = e.target.getAttribute("data-ip");
            window.location.hash = `#/devices/${ip}`;
        });
    });
}

function subnetLabelForDevice(ip) {
    const parts = String(ip || "").split(".");
    if (parts.length < 3) return "Unknown";
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function renderDeviceSubnetOptions(selectEl) {
    if (!selectEl) return;
    const subnets = [...new Set((state.devicesData || []).map(dev => subnetLabelForDevice(dev.ip)))].sort();
    const selected = state.selectedDeviceSubnet || "";
    selectEl.innerHTML = `<option value="">All subnets / VLANs</option>${subnets.map(subnet => `
        <option value="${escapeHtml(subnet)}"${subnet === selected ? " selected" : ""}>${escapeHtml(subnet)}</option>
    `).join("")}`;
}

function drawDeviceTrafficChart(timeSeries) {
    const deviceChartContainer = document.getElementById("device-chart-container");
    if (!deviceChartContainer) return;
    const width = 360;
    const height = 120;
    const pad = { top: 10, right: 12, bottom: 22, left: 52 };
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;
    deviceChartContainer.innerHTML = "";

    const points = (timeSeries || []).map(item => ({
        ts: new Date(item.bucket_ts).getTime(),
        value: Number(item.bytes || 0),
        raw: item
    })).filter(item => Number.isFinite(item.ts));

    if (points.length === 0) {
        deviceChartContainer.innerHTML = `<span class="text-muted" style="font-size: 0.813rem;">No traffic data recorded</span>`;
        return;
    }

    const minTs = Math.min(...points.map(p => p.ts));
    const maxTs = Math.max(...points.map(p => p.ts));
    const maxValue = Math.max(...points.map(p => p.value), 1);
    const tsSpan = Math.max(maxTs - minTs, 1);
    const xFor = ts => pad.left + ((ts - minTs) / tsSpan) * plotW;
    const yFor = value => pad.top + plotH - (value / maxValue) * plotH;

    const gridLines = [0, 0.5, 1].map(frac => {
        const y = pad.top + plotH - (frac * plotH);
        const label = formatBytes(maxValue * frac);
        return `<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" class="chart-grid" style="stroke: var(--border-color); stroke-dasharray: 2 2;"></line>
                <text x="${pad.left - 6}" y="${y + 3}" text-anchor="end" class="chart-axis" style="font-size: 0.65rem;">${label}</text>`;
    }).join("");

    const pathData = points.map((p, idx) => `${idx === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yFor(p.value).toFixed(2)}`).join(" ");
    const areaData = `${pathData} L ${xFor(points[points.length - 1].ts).toFixed(2)} ${pad.top + plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top + plotH} Z`;
    
    const firstLabel = formatShortTime(new Date(minTs));
    const lastLabel = formatShortTime(new Date(maxTs));

    const svgContent = `
        <svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" style="overflow: visible;">
            <defs>
                <linearGradient id="deviceAreaFill" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stop-color="var(--primary-color)" stop-opacity="0.15"></stop>
                    <stop offset="100%" stop-color="var(--primary-color)" stop-opacity="0.01"></stop>
                </linearGradient>
            </defs>
            ${gridLines}
            <path d="${areaData}" fill="url(#deviceAreaFill)"></path>
            <path d="${pathData}" class="chart-line" style="stroke: var(--primary-color); stroke-width: 1.5; fill: none;"></path>
            ${points.map(p => `<circle cx="${xFor(p.ts).toFixed(2)}" cy="${yFor(p.value).toFixed(2)}" r="2" class="chart-point" style="stroke: var(--primary-color);"><title>${new Date(p.raw.bucket_ts).toLocaleTimeString()} - Bytes: ${formatBytes(p.value)}</title></circle>`).join("")}
            <text x="${pad.left}" y="${height - 4}" class="chart-axis" style="font-size: 0.65rem;">${firstLabel}</text>
            <text x="${width - pad.right}" y="${height - 4}" text-anchor="end" class="chart-axis" style="font-size: 0.65rem;">${lastLabel}</text>
        </svg>
    `;
    deviceChartContainer.innerHTML = svgContent;
}

export async function selectDevice(ip) {
    if (!isKnownDeviceIP(ip)) {
        state.selectedDeviceIP = null;
        window.location.hash = "#/devices";
        window.showToast(`No local device profile exists for ${ip}.`, "error");
        renderDevicesView();
        return;
    }
    state.selectedDeviceIP = ip;
    renderDevices();
    const deviceDetailsPanel = document.getElementById("panel-device-details");
    if (deviceDetailsPanel) deviceDetailsPanel.scrollTop = 0;

    const detailsEmpty = document.getElementById("device-details-empty");
    const detailsContent = document.getElementById("device-details-content");
    const detailIp = document.getElementById("detail-ip");
    const detailHost = document.getElementById("detail-host");
    const detailSubnet = document.getElementById("detail-subnet");
    const detailFirstSeen = document.getElementById("detail-first-seen");
    const detailLastSeen = document.getElementById("detail-last-seen");
    const detailRiskBadgeContainer = document.getElementById("detail-risk-badge-container");
    const detailRiskExplanationSection = document.getElementById("detail-risk-explanation-section");
    const detailRiskExplanationContent = document.getElementById("detail-risk-explanation-content");
    const deviceChartContainer = document.getElementById("device-chart-container");
    const tblDevicePeers = document.getElementById("tbl-device-peers").querySelector("tbody");
    const tblDevicePorts = document.getElementById("tbl-device-ports").querySelector("tbody");
    const deviceAlertsList = document.getElementById("device-alerts-list");
    const baselineStatsContent = document.getElementById("baseline-stats-content");
    const devicePoliciesList = document.getElementById("device-policies-list");
    const btnDeviceFwRules = document.getElementById("btn-device-fw-rules");
    const inputDetailLabel = document.getElementById("input-detail-label");

    if (detailsEmpty) detailsEmpty.classList.add("hidden");
    if (detailsContent) detailsContent.classList.remove("hidden");
    
    if (detailIp) detailIp.textContent = ip;
    if (detailHost) detailHost.textContent = "Loading device profile...";
    if (detailSubnet) detailSubnet.textContent = "-";
    if (detailFirstSeen) detailFirstSeen.textContent = "-";
    if (detailLastSeen) detailLastSeen.textContent = "-";
    if (detailRiskBadgeContainer) detailRiskBadgeContainer.innerHTML = "";
    if (detailRiskExplanationSection) detailRiskExplanationSection.classList.add("hidden");
    if (detailRiskExplanationContent) detailRiskExplanationContent.innerHTML = "";
    if (deviceChartContainer) deviceChartContainer.innerHTML = `<span class="text-muted" style="font-size: 0.813rem;">Loading timeline...</span>`;
    if (tblDevicePeers) tblDevicePeers.innerHTML = `<tr><td colspan="2" class="text-muted text-center" style="font-size: 0.75rem;">Loading peers...</td></tr>`;
    if (tblDevicePorts) tblDevicePorts.innerHTML = `<tr><td colspan="2" class="text-muted text-center" style="font-size: 0.75rem;">Loading ports...</td></tr>`;
    if (deviceAlertsList) deviceAlertsList.innerHTML = `<div class="text-muted text-center" style="font-size: 0.813rem; padding: 0.5rem;">Loading alerts...</div>`;
    if (baselineStatsContent) baselineStatsContent.innerHTML = `<p class="text-muted text-center">Loading baseline profile...</p>`;

    if (btnDeviceFwRules) {
        btnDeviceFwRules.onclick = () => {
            openFirewallModal(ip);
        };
    }

    try {
        const profile = await api.fetchDeviceProfile(ip);
        if (detailHost) detailHost.textContent = profile.hostname ? `Reverse DNS: ${profile.hostname}` : "Reverse DNS: Unresolved";
        if (inputDetailLabel) inputDetailLabel.value = profile.label || "";
        if (detailSubnet) detailSubnet.textContent = profile.subnet_vlan || "Unknown";
        if (detailFirstSeen) detailFirstSeen.textContent = profile.first_seen ? formatTime(profile.first_seen) : "-";
        if (detailLastSeen) detailLastSeen.textContent = profile.last_seen ? formatTime(profile.last_seen) : "-";

        const riskInfo = profile.risk || { risk_score: 0, risk_level: "low", active_alert_count: 0 };
        const badgeClass = riskInfo.risk_level === "high" ? "risk-badge-high" : (riskInfo.risk_level === "medium" ? "risk-badge-medium" : "risk-badge-low");
        if (detailRiskBadgeContainer) {
            detailRiskBadgeContainer.innerHTML = `<span class="risk-badge ${badgeClass}" title="Active alerts: ${riskInfo.active_alert_count}">Risk Index: ${riskInfo.risk_score}</span>`;
        }

        if (riskInfo.breakdown && (riskInfo.breakdown.alert_breakdown || []).length > 0) {
            if (detailRiskExplanationSection && detailRiskExplanationContent) {
                const bd = riskInfo.breakdown;
                
                let html = `
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 0.5rem; margin-bottom: 0.5rem;">
                        <span><strong>Calculated Score:</strong> <span class="risk-badge ${badgeClass}" style="padding: 0.15rem 0.4rem; font-size: 0.75rem; border-radius: 4px; vertical-align: middle;">${riskInfo.risk_score}</span></span>
                        <span class="text-muted" style="text-transform: capitalize;"><strong>Level:</strong> ${riskInfo.risk_level}</span>
                    </div>
                    <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                `;

                (bd.alert_breakdown || []).forEach(c => {
                    const ageMinStr = Math.round(c.age_hours * 60);
                    let ageText = "";
                    if (ageMinStr < 60) {
                        ageText = `${ageMinStr} minutes ago`;
                    } else {
                        const ageHoursRounded = (c.age_hours).toFixed(1);
                        ageText = `${ageHoursRounded} hours ago`;
                    }

                    const percentDecay = Math.round(c.decay_factor * 100);

                    html += `
                        <div style="background: rgba(255,255,255,0.01); border: 1px solid var(--border-color); padding: 0.5rem; border-radius: 6px;">
                            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.25rem;">
                                <span class="font-semibold" style="font-size: 0.8rem;">${escapeHtml(c.type)}</span>
                                <span class="badge ${c.severity === "high" ? 'badge-high' : (c.severity === "medium" ? 'badge-medium' : 'badge-low')}" style="font-size: 0.65rem; padding: 0.1rem 0.3rem;">${c.severity}</span>
                            </div>
                            <p style="margin: 0 0 0.4rem 0; font-size: 0.78rem; line-height: 1.35; color: var(--text-primary);">${escapeHtml(c.description)}</p>
                            <div class="text-muted" style="display: flex; justify-content: space-between; align-items: center; font-size: 0.7rem; border-top: 1px dashed var(--border-color); padding-top: 0.25rem;">
                                <span>Triggered: <strong>${ageText}</strong></span>
                                <span>Formula: <code>${c.base_weight} (base) &times; ${percentDecay}% (decay) = +${c.contribution.toFixed(1)} pts</code></span>
                            </div>
                        </div>
                    `;
                });

                if (bd.correlation_boost > 0) {
                    html += `
                        <div style="background: rgba(251,146,60,0.05); border: 1px solid rgba(251,146,60,0.2); padding: 0.5rem; border-radius: 6px; color: #fb923c;">
                            <div class="font-semibold" style="font-size: 0.8rem; margin-bottom: 0.15rem;">Correlation Boost Applied</div>
                            <p style="margin: 0; font-size: 0.75rem; line-height: 1.3;">Correlated signature-based IDS alert (Suricata) with flow-based anomaly within 1 hour (+${bd.correlation_boost} boost)</p>
                        </div>
                    `;
                }

                html += `
                    </div>
                    <div style="border-top: 1px solid var(--border-color); padding-top: 0.5rem; margin-top: 0.25rem; display: flex; justify-content: space-between; font-size: 0.7rem; color: var(--text-secondary);">
                        <span>Thresholds:</span>
                        <span>Low: &lt; 30</span>
                        <span>Medium: 30 - 69</span>
                        <span>High: &ge; 70</span>
                    </div>
                `;

                detailRiskExplanationContent.innerHTML = html;
                detailRiskExplanationSection.classList.remove("hidden");
            }
        } else {
            if (detailRiskExplanationSection) detailRiskExplanationSection.classList.add("hidden");
        }

        if (profile.baseline) {
            const baseline = profile.baseline;
            const byteLimit = baseline.mean_bytes + (3 * baseline.stddev_bytes);
            const packetLimit = baseline.mean_packets + (3 * baseline.stddev_packets);
            const peerLimit = baseline.mean_peers + (3 * baseline.stddev_peers);

            if (baselineStatsContent) {
                baselineStatsContent.innerHTML = `
                    <div class="baseline-stat-row">
                        <span class="metric-name">Average Bytes/Min</span>
                        <span class="metric-value">${formatBytes(baseline.mean_bytes)}</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Traffic Limit (Mean + 3σ)</span>
                        <span class="metric-value text-warning" style="font-weight:700;">${formatBytes(byteLimit)}</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Average Packets/Min</span>
                        <span class="metric-value">${formatNumber(Math.round(baseline.mean_packets))} pkts</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Packet Limit (Mean + 3σ)</span>
                        <span class="metric-value text-warning" style="font-weight:700;">${formatNumber(Math.round(packetLimit))} pkts</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Average Peers/Min</span>
                        <span class="metric-value">${baseline.mean_peers.toFixed(1)}</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Peer Limit (Mean + 3σ)</span>
                        <span class="metric-value text-warning" style="font-weight:700;">${Math.round(peerLimit)} peers</span>
                    </div>
                    <p class="text-muted text-right" style="font-size:0.75rem; margin-top:0.5rem;">
                        Baseline updated: ${formatTime(baseline.updated_at)}
                    </p>
                `;
            }
        } else {
            if (baselineStatsContent) {
                baselineStatsContent.innerHTML = `
                    <div class="text-center text-muted pad-large" style="border: 1px dashed rgba(255,255,255,0.08); border-radius: 8px;">
                        No baseline computed yet.<br>
                        <span style="font-size: 0.75rem;">Profile will generate once at least 5 minutes of active traffic flows are aggregated.</span>
                    </div>
                `;
            }
        }

        if (profile.anomalies && profile.anomalies.length > 0) {
            if (deviceAlertsList) {
                deviceAlertsList.innerHTML = profile.anomalies.map(anom => {
                    const statusClass = `status-${anom.status}`;
                    const badgeClass = anom.severity === "high" ? "badge-high" : (anom.severity === "medium" ? "badge-medium" : "badge-low");
                    return `
                        <div class="device-alert-item sev-${anom.severity}">
                            <div style="flex-grow: 1; margin-right: 0.5rem;">
                                <div style="display: flex; gap: 0.4rem; align-items: center; margin-bottom: 0.15rem;">
                                    <span class="badge ${badgeClass}" style="font-size: 0.65rem; padding: 0.1rem 0.25rem;">${anom.type}</span>
                                    <span class="${statusClass}" style="font-size: 0.65rem; padding: 0.1rem 0.25rem;">${anom.status}</span>
                                </div>
                                <div style="font-weight: 500; font-size: 0.75rem; color: var(--text-primary); margin-bottom: 0.15rem;">${anom.description}</div>
                                <div class="text-muted" style="font-size: 0.65rem;">${new Date(anom.created_at).toLocaleString()}</div>
                            </div>
                            <div class="device-alert-actions" style="display: flex; gap: 0.25rem; flex-shrink: 0;">
                                ${anom.status === 'active' ?
                                    `<button class="btn-secondary btn-device-alert-triage" data-id="${anom.id}" data-action="acknowledged" style="font-size: 0.65rem; padding: 0.2rem 0.4rem;">Ack</button>
                                     <button class="btn-secondary btn-device-alert-triage" data-id="${anom.id}" data-action="silenced" style="font-size: 0.65rem; padding: 0.2rem 0.4rem;">Silence</button>` :
                                    `<button class="btn-secondary btn-device-alert-triage" data-id="${anom.id}" data-action="active" style="font-size: 0.65rem; padding: 0.2rem 0.4rem;">Reactivate</button>`
                                }
                            </div>
                        </div>
                    `;
                }).join('');

                deviceAlertsList.querySelectorAll(".btn-device-alert-triage").forEach(btn => {
                    btn.addEventListener("click", async (e) => {
                        const id = e.target.getAttribute("data-id");
                        const action = e.target.getAttribute("data-action");
                        await api.updateAnomalyStatus(id, action);
                        selectDevice(ip);
                    });
                });
            }
        } else {
            if (deviceAlertsList) {
                deviceAlertsList.innerHTML = `
                    <div class="text-muted text-center" style="font-size: 0.813rem; padding: 0.5rem; border: 1px dashed var(--border-color); border-radius: 6px;">
                        No alerts history
                    </div>
                `;
            }
        }

        if (devicePoliciesList) {
            const polSummary = profile.policy_summary || {};
            const matchingPolicies = polSummary.policies || [];
            if (matchingPolicies.length > 0) {
                devicePoliciesList.innerHTML = matchingPolicies.map(p => {
                    const statusClass = p.suppressed ? "status-silenced" : "status-active";
                    const statusText = p.suppressed ? "Silenced" : "Active";
                    const badgeClass = p.scope === "ip" ? "badge-high" : (p.scope === "subnet" ? "badge-medium" : "badge-low");
                    return `
                        <div class="device-alert-item" style="border-left: 3px solid var(--accent-color); padding: 0.4rem 0.6rem; display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;">
                            <div style="flex-grow: 1;">
                                <div style="display: flex; gap: 0.4rem; align-items: center; margin-bottom: 0.15rem;">
                                    <span class="badge ${badgeClass}" style="font-size: 0.65rem; padding: 0.1rem 0.25rem;">${p.scope}</span>
                                    <span style="font-size: 0.65rem; color: var(--text-muted); font-family: monospace;">${escapeHtml(p.target || "global")}</span>
                                </div>
                                <div style="font-weight: 600; font-size: 0.75rem; color: var(--text-primary);">${escapeHtml(p.name)}</div>
                            </div>
                            <div style="flex-shrink: 0; font-size: 0.7rem; font-weight: 600; text-transform: uppercase;" class="${statusClass}">
                                ${statusText}
                            </div>
                        </div>
                    `;
                }).join('');
            } else {
                devicePoliciesList.innerHTML = `
                    <div class="text-muted text-center" style="font-size: 0.813rem; padding: 0.5rem; border: 1px dashed var(--border-color); border-radius: 6px;">
                        No applied policies
                    </div>
                `;
            }
        }

    } catch (err) {
        console.error("Error loading device profile context: ", err);
        if (detailHost) detailHost.textContent = "Error loading profile details";
    }

    try {
        const range = trafficRangeConfig();
        const flowsData = await api.fetchDeviceFlows(ip, range.start, range.end);

        if (tblDevicePeers) {
            if (flowsData.top_peers && flowsData.top_peers.length > 0) {
                tblDevicePeers.innerHTML = flowsData.top_peers.map(peer => {
                    return `
                        <tr>
                            <td class="font-semibold"><a href="#/devices/${peer.key}" class="ip-link">${peer.key}</a></td>
                            <td>${formatBytes(peer.value)}</td>
                        </tr>
                    `;
                }).join('');
            } else {
                tblDevicePeers.innerHTML = `<tr><td colspan="2" class="text-muted text-center" style="font-size: 0.75rem;">No active peers in this range</td></tr>`;
            }
        }

        if (tblDevicePorts) {
            if (flowsData.top_ports && flowsData.top_ports.length > 0) {
                tblDevicePorts.innerHTML = flowsData.top_ports.map(port => {
                    return `
                        <tr>
                            <td class="font-semibold">Port ${port.key}</td>
                            <td>${formatBytes(port.value)}</td>
                        </tr>
                    `;
                }).join('');
            } else {
                tblDevicePorts.innerHTML = `<tr><td colspan="2" class="text-muted text-center" style="font-size: 0.75rem;">No active ports in this range</td></tr>`;
            }
        }

        drawDeviceTrafficChart(flowsData.time_series);

    } catch (err) {
        console.error("Error loading device traffic timeline/flows: ", err);
        if (deviceChartContainer) {
            deviceChartContainer.innerHTML = `<span class="text-danger" style="font-size: 0.813rem;">Failed to load traffic history</span>`;
        }
    }
}

export async function openFirewallModal(ip) {
    const modal = document.getElementById("modal-firewall");
    const targetIpField = document.getElementById("firewall-target-ip");
    const codeContent = document.getElementById("firewall-code-content");
    if (!modal) return;
    
    if (targetIpField) targetIpField.value = ip;
    if (codeContent) codeContent.textContent = "Loading rules...";
    state.activeFwTab = "mikrotik";
    
    document.querySelectorAll(".fw-tab-btn").forEach(btn => {
        if (btn.getAttribute("data-fw") === "mikrotik") {
            btn.classList.add("active");
        } else {
            btn.classList.remove("active");
        }
    });

    modal.showModal();

    try {
        state.firewallTemplates = await api.fetchFirewallTemplates(ip);
        renderFirewallCode();
    } catch (err) {
        if (codeContent) codeContent.textContent = `Error: ${err.message}`;
        window.showToast(err.message, "error");
    }
}

function renderFirewallCode() {
    const codeContent = document.getElementById("firewall-code-content");
    if (!codeContent || !state.firewallTemplates) return;
    codeContent.textContent = state.firewallTemplates[state.activeFwTab] || "No template configured.";
}

export function renderDevicesView() {
    renderDevices();
    if (state.selectedDeviceIP) {
        selectDevice(state.selectedDeviceIP);
    } else {
        const detailsEmpty = document.getElementById("device-details-empty");
        const detailsContent = document.getElementById("device-details-content");
        if (detailsEmpty) detailsEmpty.classList.remove("hidden");
        if (detailsContent) detailsContent.classList.add("hidden");
    }
}

export function bindDevicesEvents() {
    const inputDeviceSearch = document.getElementById("input-device-search");
    if (inputDeviceSearch) {
        inputDeviceSearch.addEventListener("input", () => {
            renderDevices();
        });
    }
    const selectDeviceSubnet = document.getElementById("select-device-subnet");
    if (selectDeviceSubnet) {
        selectDeviceSubnet.addEventListener("change", (e) => {
            const subnet = e.target.value;
            state.selectedDeviceSubnet = subnet;
            state.selectedDeviceIP = null;
            window.location.hash = subnet ? `#/devices/subnet/${encodeURIComponent(subnet)}` : "#/devices";
        });
    }

    const formUpdateLabel = document.getElementById("form-update-label");
    const inputDetailLabel = document.getElementById("input-detail-label");
    if (formUpdateLabel && inputDetailLabel) {
        formUpdateLabel.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!state.selectedDeviceIP) return;

            const newLabel = inputDetailLabel.value.trim();

            try {
                const resp = await fetch(`/api/devices/${state.selectedDeviceIP}/label`, {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ label: newLabel })
                });

                if (!resp.ok) throw new Error("Failed to update device label");

                window.showToast(`Label updated for ${state.selectedDeviceIP}.`);
                state.devicesData = await api.fetchDevices();
                selectDevice(state.selectedDeviceIP);
            } catch (err) {
                window.showToast(err.message, "error");
            }
        });
    }

    const btnCloseModal = document.getElementById("btn-close-modal");
    if (btnCloseModal) {
        btnCloseModal.addEventListener("click", () => {
            const modal = document.getElementById("modal-firewall");
            if (modal) modal.close();
        });
    }

    const btnCopyRules = document.getElementById("btn-copy-rules");
    if (btnCopyRules) {
        btnCopyRules.addEventListener("click", () => {
            const codeContent = document.getElementById("firewall-code-content");
            if (codeContent) {
                const code = codeContent.textContent;
                navigator.clipboard.writeText(code).then(() => {
                    window.showToast("Rules copied.");
                }).catch(err => {
                    window.showToast("Copy failed: " + err, "error");
                });
            }
        });
    }

    document.querySelectorAll(".fw-tab-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            document.querySelectorAll(".fw-tab-btn").forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            state.activeFwTab = e.target.getAttribute("data-fw");
            renderFirewallCode();
        });
    });

    const btnCloseDetails = document.getElementById("btn-close-device-details");
    const btnCloseDetailsFloating = document.getElementById("btn-close-device-details-floating");
    [btnCloseDetails, btnCloseDetailsFloating].forEach(btn => {
        if (!btn) return;
        btn.addEventListener("click", () => {
            window.location.hash = "#/devices";
        });
    });
}
