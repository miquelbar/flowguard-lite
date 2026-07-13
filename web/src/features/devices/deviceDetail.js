import { state } from '../../app/state.js';
import * as api from '../../lib/api.js';
import { isKnownDeviceIP } from '../../lib/deviceLinks.js';
import { escapeHtml, formatBytes, formatNumber, formatTime } from '../../lib/format.js';
import { trafficRangeConfig } from '../../lib/timeRanges.js';
import { drawDeviceTrafficChart } from './deviceChart.js';
import { renderDevices } from './devicesList.js';
import { openFirewallModal } from './firewallModal.js';
import { focusFirstVisibleOnMobile } from '../../components/ui/focus.js';

export function showNoDeviceSelected() {
    const detailsEmpty = document.getElementById("device-details-empty");
    const detailsContent = document.getElementById("device-details-content");
    if (detailsEmpty) detailsEmpty.classList.remove("hidden");
    if (detailsContent) detailsContent.classList.add("hidden");
}

export async function selectDevice(ip) {
    if (!isKnownDeviceIP(ip)) {
        state.selectedDeviceIP = null;
        window.location.hash = "#/devices";
        window.showToast(`No local device profile exists for ${ip}.`, "error");
        showNoDeviceSelected();
        renderDevices();
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
        btnDeviceFwRules.setAttribute("aria-label", `Generate firewall rule for ${ip}`);
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
                    const ageMinStr = (c.age_hours !== undefined && c.age_hours !== null) ? Math.round(c.age_hours * 60) : 0;
                    let ageText = "";
                    if (c.age_hours === undefined || c.age_hours === null) {
                        ageText = "unknown time ago";
                    } else if (ageMinStr < 60) {
                        ageText = `${ageMinStr} minutes ago`;
                    } else {
                        const ageHoursRounded = (c.age_hours).toFixed(1);
                        ageText = `${ageHoursRounded} hours ago`;
                    }

                    const percentDecay = (c.decay_factor !== undefined && c.decay_factor !== null) ? Math.round(c.decay_factor * 100) : 100;
                    const baseWeight = c.base_weight || 0;
                    const contribution = (c.contribution !== undefined && c.contribution !== null) ? c.contribution.toFixed(1) : "0.0";

                    html += `
                        <div style="background: rgba(255,255,255,0.01); border: 1px solid var(--border-color); padding: 0.5rem; border-radius: 6px;">
                            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.25rem;">
                                <span class="font-semibold" style="font-size: 0.8rem;">${escapeHtml(c.type || "unknown")}</span>
                                <span class="badge ${c.severity === "high" ? 'badge-high' : (c.severity === "medium" ? 'badge-medium' : 'badge-low')}" style="font-size: 0.65rem; padding: 0.1rem 0.3rem;">${c.severity || "low"}</span>
                            </div>
                            <p style="margin: 0 0 0.4rem 0; font-size: 0.78rem; line-height: 1.35; color: var(--text-primary);">${escapeHtml(c.description || "")}</p>
                            <div class="text-muted" style="display: flex; justify-content: space-between; align-items: center; font-size: 0.7rem; border-top: 1px dashed var(--border-color); padding-top: 0.25rem;">
                                <span>Triggered: <strong>${ageText}</strong></span>
                                <span>Formula: <code>${baseWeight} (base) &times; ${percentDecay}% (decay) = +${contribution} pts</code></span>
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
            const meanBytes = baseline.mean_bytes || 0;
            const stddevBytes = baseline.stddev_bytes || 0;
            const meanPackets = baseline.mean_packets || 0;
            const stddevPackets = baseline.stddev_packets || 0;
            const meanPeers = baseline.mean_peers || 0;
            const stddevPeers = baseline.stddev_peers || 0;

            const byteLimit = meanBytes + (3 * stddevBytes);
            const packetLimit = meanPackets + (3 * stddevPackets);
            const peerLimit = meanPeers + (3 * stddevPeers);

            if (baselineStatsContent) {
                baselineStatsContent.innerHTML = `
                    <div class="baseline-stat-row">
                        <span class="metric-name">Average Bytes/Min</span>
                        <span class="metric-value">${formatBytes(meanBytes)}</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Traffic Limit (Mean + 3σ)</span>
                        <span class="metric-value text-warning" style="font-weight:700;">${formatBytes(byteLimit)}</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Average Packets/Min</span>
                        <span class="metric-value">${formatNumber(Math.round(meanPackets))} pkts</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Packet Limit (Mean + 3σ)</span>
                        <span class="metric-value text-warning" style="font-weight:700;">${formatNumber(Math.round(packetLimit))} pkts</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Average Peers/Min</span>
                        <span class="metric-value">${meanPeers.toFixed(1)}</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Peer Limit (Mean + 3σ)</span>
                        <span class="metric-value text-warning" style="font-weight:700;">${Math.round(peerLimit)} peers</span>
                    </div>
                    <p class="text-muted text-right" style="font-size:0.75rem; margin-top:0.5rem;">
                        Baseline updated: ${baseline.updated_at ? formatTime(baseline.updated_at) : "unknown"}
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
                                    `<button class="btn-secondary btn-device-alert-triage" data-id="${anom.id}" data-action="acknowledged" aria-label="Acknowledge alert ${anom.id}" style="font-size: 0.65rem; padding: 0.2rem 0.4rem;">Ack</button>
                                     <button class="btn-secondary btn-device-alert-triage" data-id="${anom.id}" data-action="silenced" aria-label="Silence alert ${anom.id}" style="font-size: 0.65rem; padding: 0.2rem 0.4rem;">Silence</button>` :
                                    `<button class="btn-secondary btn-device-alert-triage" data-id="${anom.id}" data-action="active" aria-label="Reactivate alert ${anom.id}" style="font-size: 0.65rem; padding: 0.2rem 0.4rem;">Reactivate</button>`
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

        const deviceUnifiEventsList = document.getElementById("device-unifi-events-list");
        if (deviceUnifiEventsList) {
            deviceUnifiEventsList.innerHTML = `<div class="text-muted text-center" style="font-size: 0.813rem; padding: 0.5rem;">Loading events...</div>`;
        }

        let unifiEvents = [];
        try {
            unifiEvents = await api.fetchDeviceUniFiEvents(ip);
        } catch (e) {
            console.error("Failed to load device UniFi events", e);
        }

        if (deviceUnifiEventsList) {
            if (unifiEvents && unifiEvents.length > 0) {
                deviceUnifiEventsList.innerHTML = unifiEvents.map(evt => {
                    const badgeClass = evt.severity === "critical" ? "badge-high" : (evt.severity === "high" || evt.severity === "medium" ? "badge-medium" : "badge-low");
                    return `
                        <div class="device-alert-item sev-${evt.severity || 'low'}">
                            <div style="flex-grow: 1; margin-right: 0.5rem;">
                                <div style="display: flex; gap: 0.4rem; align-items: center; margin-bottom: 0.15rem;">
                                    <span class="badge ${badgeClass}" style="font-size: 0.65rem; padding: 0.1rem 0.25rem;">${escapeHtml(evt.category)}</span>
                                    <span class="text-muted" style="font-size: 0.65rem;">${escapeHtml(evt.source_gateway)}</span>
                                </div>
                                <div style="font-weight: 500; font-size: 0.75rem; color: var(--text-primary); margin-bottom: 0.15rem;">${escapeHtml(evt.summary)}</div>
                                <div class="text-muted" style="font-size: 0.65rem;">${new Date(evt.timestamp).toLocaleString()}</div>
                            </div>
                        </div>
                    `;
                }).join('');
            } else {
                deviceUnifiEventsList.innerHTML = `
                    <div class="text-muted text-center" style="font-size: 0.813rem; padding: 0.5rem; border: 1px dashed var(--border-color); border-radius: 6px;">
                        No UniFi SIEM events
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
    focusFirstVisibleOnMobile(["#btn-close-device-details-floating", "#btn-close-device-details"]);
}

