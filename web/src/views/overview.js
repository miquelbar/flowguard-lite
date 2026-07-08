import { state } from '../state.js';
import { escapeHtml, formatBytes, formatNumber, formatTime } from '../utils/format.js';

function severityClass(severity) {
    if (severity === "critical" || severity === "high") return "badge-high";
    if (severity === "medium") return "badge-medium";
    return "badge-low";
}

function riskClass(level, score) {
    if (level === "high" || score >= 70) return "risk-badge-high";
    if (level === "medium" || score >= 30) return "risk-badge-medium";
    return "risk-badge-low";
}

function protocolName(protocol) {
    const labels = { "1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP", "58": "ICMPv6" };
    return labels[String(protocol)] || `IP ${protocol}`;
}

function anomalyIP(anomaly) {
    return anomaly.device_ip || anomaly.ip || anomaly.source_ip || anomaly.src_ip || anomaly.destination_ip || "-";
}

function anomalyTime(anomaly) {
    return anomaly.detected_at || anomaly.created_at || anomaly.timestamp || anomaly.time;
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function linkForDevice(ip) {
    return `#/devices/${encodeURIComponent(ip)}`;
}

function linkForAlert(id) {
    return id ? `#/alerts/${encodeURIComponent(id)}` : "#/alerts";
}

function emptyState(text) {
    return `<div class="text-center text-muted pad-large">${escapeHtml(text)}</div>`;
}

export function renderOverviewView() {
    syncOverviewRangeButtons();
    const summary = state.securitySummaryData || {};
    const counts = summary.active_alerts_by_severity || {};
    const highCritical = (counts.critical || 0) + (counts.high || 0);

    setText("overview-active-alerts", formatNumber(summary.active_alerts_total || 0));
    setText("overview-max-risk", formatNumber(summary.max_risk_score || 0));
    setText("overview-elevated-devices", formatNumber(summary.elevated_risk_devices || 0));
    setText("overview-critical-alerts", formatNumber(highCritical));

    renderSeveritySummary(counts);
    renderAttackTimeline();
    renderTopThreatActors(summary.top_risk_devices || []);
    renderRecentHighSeverity(summary.recent_high_alerts || []);
    renderRiskDistribution(summary.risk_distribution || {});
    renderDetectionCoverage(summary);
    renderProtocolDonut();
    renderTopDevicesBars();
    renderRateSparklines();
    renderSubnetSparklines();
    renderDeviceHeatmap();
    renderCollectorHealth(summary.collector || null);
}

function renderSeveritySummary(counts) {
    const el = document.getElementById("overview-severity-summary");
    if (!el) return;
    const rows = [
        ["critical", counts.critical || 0],
        ["high", counts.high || 0],
        ["medium", counts.medium || 0],
        ["low", counts.low || 0]
    ];
    el.innerHTML = rows.map(([severity, count]) => `
        <div class="overview-metric-row">
            <span><span class="badge ${severityClass(severity)}">${severity}</span></span>
            <strong>${formatNumber(count)}</strong>
        </div>
    `).join("");
}

function renderAttackTimeline() {
    const el = document.getElementById("overview-attack-timeline");
    if (!el) return;
    const points = (state.securityTimelineData || []).slice(-12);
    if (points.length === 0) {
        el.innerHTML = emptyState("No active attack clusters in the selected range.");
        return;
    }

    const max = Math.max(...points.map(p => p.total || 0), 1);
    el.innerHTML = `<div class="attack-timeline-track">${points.map(point => {
        const counts = point.counts || {};
        const severity = counts.critical || counts.high ? "high" : (counts.medium ? "medium" : "low");
        const height = 18 + ((point.total || 0) / max) * 62;
        return `<div class="attack-timeline-point" title="${formatTime(point.timestamp)} - ${point.total || 0} alerts">
            <span class="attack-bar ${severityClass(severity)}" style="height:${height}px"></span>
            <span class="attack-count">${formatNumber(point.total || 0)}</span>
        </div>`;
    }).join("")}</div>`;
}

function renderTopThreatActors(devices) {
    const body = document.querySelector("#overview-top-actors tbody");
    if (!body) return;
    const rows = [...devices].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)).slice(0, 8);
    if (rows.length === 0) {
        body.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No elevated-risk devices.</td></tr>`;
        return;
    }
    body.innerHTML = rows.map(row => `
        <tr>
            <td><a href="${linkForDevice(row.ip)}" class="ip-link">${escapeHtml(row.ip)}</a></td>
            <td class="text-right">${formatNumber(row.active_alert_count || 0)}</td>
            <td><span class="badge ${severityClass(row.risk_level === "high" ? "high" : "medium")}">${escapeHtml(row.risk_level || "medium")}</span></td>
            <td class="text-right">${formatNumber(row.risk_score || 0)}</td>
        </tr>
    `).join("");
}

function renderRecentHighSeverity(alerts) {
    const body = document.querySelector("#overview-recent-alerts tbody");
    if (!body) return;
    const rows = alerts.slice(0, 10);
    if (rows.length === 0) {
        body.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No high-severity active alerts.</td></tr>`;
        return;
    }
    body.innerHTML = rows.map(alert => `
        <tr data-alert-id="${alert.id || ""}" class="overview-alert-row">
            <td><a href="${linkForAlert(alert.id)}" class="ip-link">${escapeHtml(anomalyIP(alert))}</a></td>
            <td>${escapeHtml(alert.type || alert.anomaly_type || "alert")}</td>
            <td><span class="badge ${severityClass(alert.severity)}">${escapeHtml(alert.severity || "low")}</span></td>
            <td class="text-right">${formatTime(anomalyTime(alert))}</td>
        </tr>
    `).join("");
}

function renderRiskDistribution(counts) {
    const el = document.getElementById("overview-risk-distribution");
    if (!el) return;
    const normalized = { low: counts.low || 0, medium: counts.medium || 0, high: counts.high || 0 };
    const total = Math.max(normalized.low + normalized.medium + normalized.high, 1);
    el.innerHTML = Object.entries(normalized).map(([level, count]) => {
        const pct = (count / total) * 100;
        return `<div class="overview-risk-row">
            <span class="risk-badge ${riskClass(level, level === "high" ? 70 : level === "medium" ? 30 : 0)}">${level}</span>
            <div class="overview-risk-track"><span style="width:${Math.max(pct, count ? 4 : 0)}%"></span></div>
            <strong>${formatNumber(count)}</strong>
        </div>`;
    }).join("");
}

function renderDetectionCoverage(summary) {
    const el = document.getElementById("overview-detection-coverage");
    if (!el) return;
    const thresholds = summary.ddos_thresholds || {};
    const rows = [
        ["Behavior anomalies", "Enabled", "badge-low"],
        ["DDoS thresholds", `${formatNumber(thresholds.pps || 0)} pps`, "badge-medium"],
        ["Suricata ingest", summary.suricata_configured ? "Configured" : "Not configured", summary.suricata_configured ? "badge-low" : "badge-medium"],
        ["Notification routing", summary.notification_configured ? "Configured" : "No channel", summary.notification_configured ? "badge-low" : "badge-medium"]
    ];
    el.innerHTML = rows.map(([name, value, cls]) => `
        <div class="overview-metric-row">
            <span>${escapeHtml(name)}</span>
            <span class="badge ${cls}">${escapeHtml(value)}</span>
        </div>
    `).join("");
}

function renderProtocolDonut() {
    const el = document.getElementById("overview-protocol-donut");
    if (!el) return;
    const data = state.overviewProtocolsData || [];
    if (data.length === 0) {
        el.innerHTML = emptyState("No protocol data in the selected range.");
        return;
    }
    const total = data.reduce((sum, item) => sum + Number(item.bytes || 0), 0) || 1;
    const colors = ["#38bdf8", "#f59e0b", "#22c55e", "#ef4444", "#94a3b8"];
    let offset = 0;
    const segments = data.map((item, idx) => {
        const pct = Number(item.bytes || 0) / total;
        const dash = `${(pct * 100).toFixed(2)} ${Math.max(0, 100 - pct * 100).toFixed(2)}`;
        const segment = `<circle r="15.9" cx="18" cy="18" fill="transparent" stroke="${colors[idx % colors.length]}" stroke-width="6" stroke-dasharray="${dash}" stroke-dashoffset="${(-offset).toFixed(2)}"></circle>`;
        offset += pct * 100;
        return segment;
    }).join("");
    const legend = data.map((item, idx) => {
        const pct = (Number(item.bytes || 0) / total) * 100;
        return `<div class="overview-legend-row">
            <span><i style="background:${colors[idx % colors.length]}"></i>${escapeHtml(protocolName(item.key))}</span>
            <strong>${pct.toFixed(0)}%</strong>
        </div>`;
    }).join("");
    el.innerHTML = `
        <svg class="overview-donut" viewBox="0 0 36 36" role="img" aria-label="Protocol distribution">
            ${segments}
        </svg>
        <div class="overview-donut-legend">${legend}</div>
    `;
}

function renderTopDevicesBars() {
    const el = document.getElementById("overview-top-devices-bars");
    if (!el) return;
    const data = state.overviewTopDevicesData || [];
    if (data.length === 0) {
        el.innerHTML = emptyState("No known device traffic in the selected range.");
        return;
    }
    const max = Math.max(...data.map(item => Number(item.bytes || 0)), 1);
    el.innerHTML = data.slice(0, 5).map(item => {
        const pct = (Number(item.bytes || 0) / max) * 100;
        return `<div class="overview-bar-row">
            <div class="overview-bar-label"><a href="${linkForDevice(item.key)}" class="ip-link">${escapeHtml(item.key)}</a><strong>${formatBytes(item.bytes || 0)}</strong></div>
            <div class="overview-risk-track"><span style="width:${Math.max(pct, 3)}%"></span></div>
        </div>`;
    }).join("");
}

function renderRateSparklines() {
    const el = document.getElementById("overview-rate-sparklines");
    if (!el) return;
    const series = state.trafficSeriesData || [];
    if (series.length === 0) {
        el.innerHTML = emptyState("No rate data in the selected range.");
        return;
    }
    const bucketSeconds = bucketSecondsForRange();
    const rows = [
        ["Bytes/s", series.map(item => Number(item.bytes || 0) / bucketSeconds), formatBytes],
        ["Packets/s", series.map(item => Number(item.packets || 0) / bucketSeconds), n => formatNumber(Math.round(n))],
        ["Flows/s", series.map(item => Number(item.flows || 0) / bucketSeconds), n => formatNumber(Math.round(n))]
    ];
    el.innerHTML = rows.map(([label, values, formatter]) => `
        <div class="overview-spark-row">
            <div><strong>${label}</strong><span>${formatter(values[values.length - 1] || 0)}</span></div>
            ${sparkline(values)}
        </div>
    `).join("");
}

function renderSubnetSparklines() {
    const el = document.getElementById("overview-subnet-sparklines");
    if (!el) return;
    const heatmap = state.overviewHeatmapData || [];
    if (heatmap.length === 0) {
        el.innerHTML = emptyState("No subnet activity in the selected range.");
        return;
    }
    const grouped = new Map();
    heatmap.forEach(cell => {
        const subnet = subnetLabelFor(cell.ip);
        if (!grouped.has(subnet)) grouped.set(subnet, Array(24).fill(0));
        grouped.get(subnet)[cell.hour] += Number(cell.bytes || 0);
    });
    el.innerHTML = [...grouped.entries()].slice(0, 5).map(([subnet, values]) => `
        <div class="overview-spark-row">
            <div><strong>${escapeHtml(subnet)}</strong><span>${formatBytes(values.reduce((a, b) => a + b, 0))}</span></div>
            ${sparkline(values)}
        </div>
    `).join("");
}

function renderDeviceHeatmap() {
    const el = document.getElementById("overview-device-heatmap");
    if (!el) return;
    const heatmap = state.overviewHeatmapData || [];
    if (heatmap.length === 0) {
        el.innerHTML = emptyState("No device activity heatmap data in the selected range.");
        return;
    }
    const byIP = new Map();
    let max = 1;
    heatmap.forEach(cell => {
        if (!byIP.has(cell.ip)) byIP.set(cell.ip, Array(24).fill(0));
        byIP.get(cell.ip)[cell.hour] += Number(cell.bytes || 0);
        max = Math.max(max, byIP.get(cell.ip)[cell.hour]);
    });
    const hourLabels = Array.from({ length: 24 }, (_, i) => `<span>${i}</span>`).join("");
    const rows = [...byIP.entries()].slice(0, 10).map(([ip, values]) => `
        <div class="heatmap-row">
            <a href="${linkForDevice(ip)}" class="ip-link heatmap-label">${escapeHtml(ip)}</a>
            <div class="heatmap-cells">
                ${values.map(val => `<span title="${formatBytes(val)}" style="opacity:${Math.max(0.12, val / max)}"></span>`).join("")}
            </div>
        </div>
    `).join("");
    el.innerHTML = `<div class="heatmap-hours"><span></span><div>${hourLabels}</div></div>${rows}`;
}

function renderCollectorHealth(collector) {
    const el = document.getElementById("overview-collector-health");
    if (!el) return;
    const samples = state.overviewCollectorHealthData || [];
    const latest = samples[samples.length - 1] || collector;
    if (!latest) {
        el.innerHTML = emptyState("Collector status unavailable.");
        return;
    }
    const received = Number(latest.packets_received || 0);
    const drops = Number(latest.packets_dropped || 0);
    const errors = Number(latest.decode_errors || 0);
    const dropPct = received ? (drops / received) * 100 : 0;
    const errPct = received ? (errors / received) * 100 : 0;
    const dropTrend = samples.map(item => Number(item.packets_dropped || 0));
    const errorTrend = samples.map(item => Number(item.decode_errors || 0));
    const queueTrend = samples.map(item => Number(item.queue_depth || 0));
    el.innerHTML = `
        <div class="overview-gauge">
            <strong>${dropPct.toFixed(2)}%</strong>
            <span>drop rate</span>
        </div>
        <div class="overview-metric-row"><span>Packets received</span><strong>${formatNumber(received)}</strong></div>
        <div class="overview-metric-row"><span>Dropped packets</span><strong>${formatNumber(drops)}</strong></div>
        <div class="overview-metric-row"><span>Decode errors</span><strong>${formatNumber(errors)} (${errPct.toFixed(2)}%)</strong></div>
        <div class="overview-metric-row"><span>Queue depth</span><strong>${formatNumber(latest.queue_depth || 0)}</strong></div>
        <div class="overview-spark-row">
            <div><strong>Drops trend</strong><span>${formatNumber(drops)}</span></div>
            ${sparkline(dropTrend.length ? dropTrend : [drops])}
        </div>
        <div class="overview-spark-row">
            <div><strong>Errors trend</strong><span>${formatNumber(errors)}</span></div>
            ${sparkline(errorTrend.length ? errorTrend : [errors])}
        </div>
        <div class="overview-spark-row">
            <div><strong>Queue trend</strong><span>${formatNumber(latest.queue_depth || 0)}</span></div>
            ${sparkline(queueTrend.length ? queueTrend : [latest.queue_depth || 0])}
        </div>
    `;
}

function sparkline(values) {
    const max = Math.max(...values, 1);
    const width = 140;
    const height = 34;
    const step = values.length > 1 ? width / (values.length - 1) : width;
    const points = values.map((value, idx) => {
        const x = idx * step;
        const y = height - (Number(value || 0) / max) * (height - 4) - 2;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(" ");
    return `<svg class="overview-sparkline" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
        <polyline points="${points}" fill="none" stroke="currentColor" stroke-width="2"></polyline>
    </svg>`;
}

function bucketSecondsForRange() {
    return { "1h": 60, "6h": 300, "24h": 900, "7d": 3600 }[state.activeTrafficRange] || 900;
}

function subnetLabelFor(ip) {
    const parts = String(ip || "").split(".");
    if (parts.length < 3) return "Unknown";
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function syncOverviewRangeButtons() {
    document.querySelectorAll(".overview-range-btn").forEach(btn => {
        btn.classList.toggle("active", btn.getAttribute("data-range") === state.activeTrafficRange);
    });
}

export function bindOverviewEvents(onReload) {
    document.querySelectorAll(".overview-range-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            document.querySelectorAll(".overview-range-btn").forEach(b => b.classList.remove("active"));
            e.currentTarget.classList.add("active");
            state.activeTrafficRange = e.currentTarget.getAttribute("data-range");
            if (onReload) onReload();
        });
    });
}
