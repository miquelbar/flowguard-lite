import { state } from '../../app/state.js';
import { deviceIPCell } from '../../lib/deviceLinks.js';
import { escapeHtml, formatBytes, formatNumber, formatTime } from '../../lib/format.js';
import { activeRangeBucketSeconds } from '../../lib/timeRanges.js';
import {
    anomalyIP,
    anomalyTime,
    emptyState,
    errorState,
    linkForAlert,
    overviewError,
    protocolName,
    riskClass,
    setText,
    severityClass,
    subnetLabelFor
} from './overviewSupport.js';
import { collectorTimestamp, timeSparkline, timestampForHeatmapSlot } from './overviewSparklines.js';

export function renderSeveritySummary(counts) {
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



export function renderWindowSummary() {
    const series = state.trafficSeriesData || [];
    const errors = [
        overviewError("trafficSeries"),
    ].filter(Boolean);
    if (errors.length > 0) {
        setText("overview-window-traffic", "-");
        setText("overview-window-packets", "-");
        setText("overview-window-flows", "-");
        return;
    }

    const totals = series.reduce((acc, item) => {
        acc.bytes += Number(item.bytes || 0);
        acc.packets += Number(item.packets || 0);
        acc.flows += Number(item.flows || 0);
        return acc;
    }, { bytes: 0, packets: 0, flows: 0 });

    setText("overview-window-traffic", formatBytes(totals.bytes));
    setText("overview-window-packets", formatNumber(totals.packets));
    setText("overview-window-flows", formatNumber(totals.flows));
}



export function renderTopThreatActors(devices) {
    const body = document.querySelector("#overview-top-actors tbody");
    if (!body) return;
    const rows = [...devices].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)).slice(0, 8);
    if (rows.length === 0) {
        body.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No elevated-risk devices.</td></tr>`;
        return;
    }
    body.innerHTML = rows.map(row => `
        <tr>
            <td>${deviceIPCell(row.ip)}</td>
            <td class="text-right">${formatNumber(row.active_alert_count || 0)}</td>
            <td><span class="badge ${severityClass(row.risk_level === "high" ? "high" : "medium")}">${escapeHtml(row.risk_level || "medium")}</span></td>
            <td class="text-right">${formatNumber(row.risk_score || 0)}</td>
        </tr>
    `).join("");
}



export function renderRecentHighSeverity(alerts) {
    const body = document.querySelector("#overview-recent-alerts tbody");
    if (!body) return;
    const rows = alerts.slice(0, 10);
    if (rows.length === 0) {
        body.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No high-severity active alerts.</td></tr>`;
        return;
    }
    body.innerHTML = rows.map(alert => `
        <tr data-alert-id="${alert.id || ""}" class="overview-alert-row severity-${alert.severity || "low"}">
            <td><a href="${linkForAlert(alert.id)}" class="ip-link">${escapeHtml(anomalyIP(alert))}</a></td>
            <td>${escapeHtml(alert.type || alert.anomaly_type || "alert")}</td>
            <td><span class="badge ${severityClass(alert.severity)}">${escapeHtml(alert.severity || "low")}</span></td>
            <td class="text-right">${formatTime(anomalyTime(alert))}</td>
        </tr>
    `).join("");
}



export function renderRiskDistribution(counts) {
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



export function renderDetectionCoverage(summary) {
    const el = document.getElementById("overview-detection-coverage");
    if (!el) return;
    const thresholds = summary.ddos_thresholds || {};
    const rows = [
        ["Behavior anomalies", "Enabled", "badge-low"],
        ["DDoS thresholds", `${formatNumber(thresholds.pps || 0)} pps`, "badge-medium"],
        ["Suricata ingest", summary.suricata_configured ? "Configured" : "Not configured", summary.suricata_configured ? "badge-low" : "badge-medium"],
        ["UniFi SIEM ingest", summary.unifi_configured ? "Configured" : "Not configured", summary.unifi_configured ? "badge-low" : "badge-medium"],
        ["Notification routing", summary.notification_configured ? "Configured" : "No channel", summary.notification_configured ? "badge-low" : "badge-medium"]
    ];
    el.innerHTML = rows.map(([name, value, cls]) => `
        <div class="overview-metric-row">
            <span>${escapeHtml(name)}</span>
            <span class="badge ${cls}">${escapeHtml(value)}</span>
        </div>
    `).join("");
}



export function renderProtocolDonut() {
    const el = document.getElementById("overview-protocol-donut");
    if (!el) return;
    const error = overviewError("protocols");
    if (error) {
        el.innerHTML = errorState(`Protocol stats unavailable: ${error}`);
        return;
    }
    const data = state.overviewProtocolsData || [];
    if (data.length === 0) {
        el.innerHTML = emptyState("No flow aggregate data in the selected range. Start NetFlow/sFlow/passive capture or run the development seed.");
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



export function renderTopDevicesBars() {
    const el = document.getElementById("overview-top-devices-bars");
    if (!el) return;
    const error = overviewError("topDevices");
    if (error) {
        el.innerHTML = errorState(`Top-device stats unavailable: ${error}`);
        return;
    }
    const data = state.overviewTopDevicesData || [];
    if (data.length === 0) {
        el.innerHTML = emptyState("No known-device traffic in the selected range. Devices must be discovered or seeded before this panel can rank them.");
        return;
    }
    const max = Math.max(...data.map(item => Number(item.bytes || 0)), 1);
    el.innerHTML = data.slice(0, 5).map(item => {
        const pct = (Number(item.bytes || 0) / max) * 100;
        return `<div class="overview-bar-row">
            <div class="overview-bar-label">${deviceIPCell(item.key)}<strong>${formatBytes(item.bytes || 0)}</strong></div>
            <div class="overview-risk-track"><span style="width:${Math.max(pct, 3)}%"></span></div>
        </div>`;
    }).join("");
}



export function renderRateSparklines() {
    const el = document.getElementById("overview-rate-sparklines");
    if (!el) return;
    const error = overviewError("trafficSeries");
    if (error) {
        el.innerHTML = errorState(`Rate data unavailable: ${error}`);
        return;
    }
    const series = state.trafficSeriesData || [];
    if (series.length === 0) {
        el.innerHTML = emptyState("No aggregate traffic buckets in the selected range. Verify telemetry ingestion or reseed demo data.");
        return;
    }
    const bucketSeconds = activeRangeBucketSeconds();
    const rows = [
        ["Bytes/s", series.map(item => ({ timestamp: item.timestamp, value: Number(item.bytes || 0) / bucketSeconds })), formatBytes],
        ["Packets/s", series.map(item => ({ timestamp: item.timestamp, value: Number(item.packets || 0) / bucketSeconds })), n => formatNumber(Math.round(n))],
        ["Flows/s", series.map(item => ({ timestamp: item.timestamp, value: Number(item.flows || 0) / bucketSeconds })), n => formatNumber(Math.round(n))]
    ];
    el.innerHTML = rows.map(([label, points, formatter]) => `
        <div class="overview-spark-row">
            <div><strong>${label}</strong><span>${formatter(points[points.length - 1]?.value || 0)}</span></div>
            ${timeSparkline(points)}
        </div>
    `).join("");
}



export function renderSubnetSparklines() {
    const el = document.getElementById("overview-subnet-sparklines");
    if (!el) return;
    const error = overviewError("heatmap");
    if (error) {
        el.innerHTML = errorState(`Subnet activity unavailable: ${error}`);
        return;
    }
    const heatmap = state.overviewHeatmapData || [];
    if (heatmap.length === 0) {
        el.innerHTML = emptyState("No top-device heatmap data in the selected range. Verify flow aggregates and device inventory.");
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
            <div><strong><a href="#/devices/subnet/${encodeURIComponent(subnet)}" class="ip-link">${escapeHtml(subnet)}</a></strong><span>${formatBytes(values.reduce((a, b) => a + b, 0))}</span></div>
            ${timeSparkline(values.map((value, idx) => ({ timestamp: timestampForHeatmapSlot(idx), value })))}
        </div>
    `).join("");
}



export function renderDeviceHeatmap() {
    const el = document.getElementById("overview-device-heatmap");
    if (!el) return;
    const error = overviewError("heatmap");
    if (error) {
        el.innerHTML = errorState(`Device heatmap unavailable: ${error}`);
        return;
    }
    const heatmap = state.overviewHeatmapData || [];
    if (heatmap.length === 0) {
        el.innerHTML = emptyState("No device activity heatmap data in the selected range. Verify flow aggregates and device inventory.");
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
            <span class="heatmap-label">${deviceIPCell(ip)}</span>
            <div class="heatmap-cells">
                ${values.map(val => `<span title="${formatBytes(val)}" style="opacity:${Math.max(0.12, val / max)}"></span>`).join("")}
            </div>
        </div>
    `).join("");
    el.innerHTML = `<div class="heatmap-hours"><span></span><div>${hourLabels}</div></div>${rows}`;
}



export function renderCollectorHealth(collector) {
    const el = document.getElementById("overview-collector-health");
    if (!el) return;
    const error = overviewError("collectorHealth");
    if (error) {
        el.innerHTML = errorState(`Collector health unavailable: ${error}`);
        return;
    }
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
    const sources = latest.sources || collector?.sources || [];
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
            ${timeSparkline((dropTrend.length ? dropTrend : [drops]).map((value, idx) => ({ timestamp: collectorTimestamp(samples[idx], idx, dropTrend.length || 1), value })))}
        </div>
        <div class="overview-spark-row">
            <div><strong>Errors trend</strong><span>${formatNumber(errors)}</span></div>
            ${timeSparkline((errorTrend.length ? errorTrend : [errors]).map((value, idx) => ({ timestamp: collectorTimestamp(samples[idx], idx, errorTrend.length || 1), value })))}
        </div>
        <div class="overview-spark-row">
            <div><strong>Queue trend</strong><span>${formatNumber(latest.queue_depth || 0)}</span></div>
            ${timeSparkline((queueTrend.length ? queueTrend : [latest.queue_depth || 0]).map((value, idx) => ({ timestamp: collectorTimestamp(samples[idx], idx, queueTrend.length || 1), value })))}
        </div>
        ${collectorSourcesTable(sources)}
    `;
}

function collectorSourcesTable(sources) {
    if (!sources.length) {
        return `<div class="empty-state compact">No collector sources reported.</div>`;
    }
    const rows = sources.map(source => {
        const status = source.status || (source.enabled ? "configured" : "disabled");
        const statusClass = status === "listening" ? "status-active" : (status === "disabled" ? "status-silenced" : "status-acknowledged");
        return `
            <tr>
                <td><span class="badge badge-label">${escapeHtml(source.kind || source.id || "unknown")}</span></td>
                <td>${source.port ? escapeHtml(String(source.port)) : "-"}</td>
                <td><span class="${statusClass}">${escapeHtml(status)}</span></td>
                <td class="text-right">${formatNumber(source.packets || 0)}</td>
                <td class="text-right">${formatNumber(source.drops || 0)}</td>
                <td class="text-right">${formatNumber(source.decode_errors || 0)}</td>
            </tr>
        `;
    }).join("");
    return `
        <div class="collector-source-list">
            <div class="section-mini-title">Sources</div>
            <table class="compact-table">
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Port</th>
                        <th>Status</th>
                        <th class="text-right">Packets</th>
                        <th class="text-right">Drops</th>
                        <th class="text-right">Errors</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

