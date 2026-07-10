import { state } from '../state.js';
import { escapeHtml, formatBytes, formatNumber, formatTime } from '../utils/format.js';
import { activeRangeBucketSeconds, activeRangeDurationMs, isDayRange } from '../utils/timeRanges.js';
import { deviceIPCell } from '../utils/deviceLinks.js';

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

function linkForAlert(id) {
    return id ? `#/alerts/${encodeURIComponent(id)}` : "#/alerts";
}

function emptyState(text) {
    return `<div class="text-center text-muted pad-large">${escapeHtml(text)}</div>`;
}

function errorState(text) {
    return `<div class="overview-error-state pad-large">${escapeHtml(text)}</div>`;
}

function overviewError(key) {
    return state.overviewErrors?.[key] || "";
}

export function renderOverviewView() {
    syncOverviewRangeButtons();
    const summary = state.securitySummaryData || {};
    const counts = summary.active_alerts_by_severity || {};

    setText("overview-max-risk", formatNumber(summary.max_risk_score || 0));
    setText("overview-elevated-devices", formatNumber(summary.elevated_risk_devices || 0));

    renderWindowSummary();
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

function renderWindowSummary() {
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

function renderAttackTimeline() {
    const el = document.getElementById("overview-attack-timeline");
    if (!el) return;
    const error = overviewError("timeline");
    if (error) {
        el.innerHTML = errorState(`Attack timeline unavailable: ${error}`);
        return;
    }
    const points = continuousTimelineSlots(state.securityTimelineData || []);
    const hasAlerts = points.some(point => (point.total || 0) > 0);

    const max = Math.max(...points.map(p => p.total || 0), 1);
    const width = 900;
    const height = 220;
    const pad = { top: 18, right: 18, bottom: 42, left: 54 };
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;
    const barGap = 4;
    const barW = Math.max(6, (plotW / points.length) - barGap);
    const xFor = idx => pad.left + idx * (plotW / points.length) + ((plotW / points.length) - barW) / 2;
    const yFor = value => pad.top + plotH - (value / max) * plotH;
    const yTicks = [0, 0.25, 0.5, 0.75, 1].map(frac => {
        const value = Math.round(max * frac);
        const y = yFor(value);
        return `<line x1="${pad.left}" x2="${width - pad.right}" y1="${y}" y2="${y}" class="chart-grid"></line>
            <text x="${pad.left - 9}" y="${y + 4}" text-anchor="end" class="chart-axis">${formatNumber(value)}</text>`;
    }).join("");
    const xTicks = points.map((point, idx) => {
        const every = points.length <= 12 ? 2 : 4;
        if (idx !== 0 && idx !== points.length - 1 && idx % every !== 0) return "";
        const x = xFor(idx) + barW / 2;
        return `<text x="${x}" y="${height - 12}" text-anchor="middle" class="chart-axis">${escapeHtml(timelineTickLabel(point.timestamp))}</text>`;
    }).join("");
    const bars = points.map((point, idx) => {
        const counts = point.counts || {};
        const severity = counts.critical || counts.high ? "high" : (counts.medium ? "medium" : "low");
        const total = point.total || 0;
        const barH = total ? Math.max(3, (total / max) * plotH) : 2;
        const x = xFor(idx);
        const y = pad.top + plotH - barH;
        const emptyClass = total ? "" : " attack-svg-bar-empty";
        return `<g class="attack-timeline-point"
            data-timestamp="${escapeHtml(point.timestamp)}"
            data-total="${total}"
            data-critical="${counts.critical || 0}"
            data-high="${counts.high || 0}"
            data-medium="${counts.medium || 0}"
            data-low="${counts.low || 0}">
            <rect class="attack-svg-bar ${severityClass(severity)}${emptyClass}" x="${x.toFixed(2)}" y="${y.toFixed(2)}" width="${barW.toFixed(2)}" height="${barH.toFixed(2)}" rx="3"></rect>
            <rect class="attack-hitbox" x="${x.toFixed(2)}" y="${pad.top}" width="${barW.toFixed(2)}" height="${plotH}" fill="transparent"></rect>
        </g>`;
    }).join("");
    const note = hasAlerts ? "" : `<div class="attack-timeline-note text-center text-muted">No active attack clusters in the selected range.</div>`;
    el.innerHTML = `<div class="attack-timeline-inner">${note}
        <svg class="attack-timeline-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Attack timeline: hours on X axis and active alert occurrences on Y axis">
            ${yTicks}
            <line x1="${pad.left}" x2="${width - pad.right}" y1="${pad.top + plotH}" y2="${pad.top + plotH}" class="chart-axis-line"></line>
            <line x1="${pad.left}" x2="${pad.left}" y1="${pad.top}" y2="${pad.top + plotH}" class="chart-axis-line"></line>
            ${bars}
            ${xTicks}
            <text x="${pad.left}" y="${height - 2}" class="chart-axis">time</text>
            <text x="12" y="${pad.top + 4}" class="chart-axis" transform="rotate(-90 12 ${pad.top + 4})">occurrences</text>
        </svg>
    </div>`;
    bindAttackTimelineTooltips(el);
}

function timelineTickLabel(timestamp) {
    const date = new Date(timestamp);
    if (isDayRange()) {
        return date.toLocaleDateString([], { month: "short", day: "numeric" });
    }
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function bindAttackTimelineTooltips(root) {
    const tooltip = document.getElementById("chart-tooltip");
    if (!tooltip) return;
    const hide = () => {
        tooltip.style.display = "none";
    };
    root.querySelectorAll(".attack-timeline-point").forEach(point => {
        point.addEventListener("mousemove", (e) => {
            const total = Number(point.dataset.total || 0);
            const critical = Number(point.dataset.critical || 0);
            const high = Number(point.dataset.high || 0);
            const medium = Number(point.dataset.medium || 0);
            const low = Number(point.dataset.low || 0);
            tooltip.innerHTML = `
                <div style="font-weight:600;margin-bottom:0.35rem;">${formatTime(point.dataset.timestamp)}</div>
                <div>Active alerts in bucket: <strong>${formatNumber(total)}</strong></div>
                <div style="margin-top:0.35rem;display:grid;grid-template-columns:auto auto;gap:0.18rem 0.75rem;">
                    <span>Critical</span><strong>${formatNumber(critical)}</strong>
                    <span>High</span><strong>${formatNumber(high)}</strong>
                    <span>Medium</span><strong>${formatNumber(medium)}</strong>
                    <span>Low</span><strong>${formatNumber(low)}</strong>
                </div>
            `;
            tooltip.style.display = "block";
            const rect = tooltip.getBoundingClientRect();
            let left = e.clientX + 16;
            let top = e.clientY - rect.height / 2;
            if (left + rect.width + 8 > window.innerWidth) left = e.clientX - rect.width - 16;
            if (top < 8) top = 8;
            if (top + rect.height + 8 > window.innerHeight) top = window.innerHeight - rect.height - 8;
            tooltip.style.left = `${left}px`;
            tooltip.style.top = `${top}px`;
        });
        point.addEventListener("mouseleave", hide);
    });
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
            <td>${deviceIPCell(row.ip)}</td>
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

function renderTopDevicesBars() {
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

function renderRateSparklines() {
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

function renderSubnetSparklines() {
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

function renderDeviceHeatmap() {
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

function renderCollectorHealth(collector) {
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
    `;
}

function timeSparkline(points) {
    const clean = (points || []).map(point => ({
        ts: new Date(point.timestamp).getTime(),
        value: Number(point.value || 0)
    })).filter(point => Number.isFinite(point.ts));
    if (clean.length === 0) return `<svg class="overview-sparkline" viewBox="0 0 180 54" preserveAspectRatio="none"></svg>`;

    const max = Math.max(...clean.map(point => point.value), 1);
    const width = 180;
    const height = 54;
    const pad = { top: 4, right: 6, bottom: 18, left: 4 };
    const domain = selectedRangeDomain();
    const span = Math.max(domain.endMs - domain.startMs, 1);
    const xFor = ts => pad.left + ((ts - domain.startMs) / span) * (width - pad.left - pad.right);
    const yFor = value => pad.top + (height - pad.top - pad.bottom) - (value / max) * (height - pad.top - pad.bottom);
    const pathPoints = clean.map(point => {
        const x = Math.max(pad.left, Math.min(width - pad.right, xFor(point.ts)));
        const y = yFor(point.value);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(" ");
    const ticks = timeTicks(domain.startMs, domain.endMs, 2);
    return `<svg class="overview-sparkline overview-time-sparkline" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Time-series sparkline">
        <line x1="${pad.left}" x2="${width - pad.right}" y1="${height - pad.bottom}" y2="${height - pad.bottom}" class="chart-axis-line"></line>
        <polyline points="${pathPoints}" fill="none" stroke="currentColor" stroke-width="2"></polyline>
        ${ticks.map(tick => {
            const x = xFor(tick);
            return `<text x="${x.toFixed(1)}" y="${height - 4}" text-anchor="${tick === domain.startMs ? "start" : "end"}" class="chart-axis">${escapeHtml(shortTimeLabel(tick))}</text>`;
        }).join("")}
    </svg>`;
}

function rangeDurationMs() {
    return activeRangeDurationMs();
}

function selectedRangeDomain() {
    const endMs = Date.now();
    return { startMs: endMs - rangeDurationMs(), endMs };
}

function timeTicks(startMs, endMs, count) {
    if (count <= 1) return [startMs];
    const step = (endMs - startMs) / (count - 1);
    return Array.from({ length: count }, (_, idx) => startMs + step * idx);
}

function shortTimeLabel(timestamp) {
    const date = new Date(timestamp);
    if (isDayRange()) {
        return date.toLocaleDateString([], { month: "short", day: "numeric" });
    }
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function timestampForHeatmapSlot(slot) {
    const { startMs, endMs } = selectedRangeDomain();
    return new Date(startMs + ((endMs - startMs) / 24) * slot).toISOString();
}

function collectorTimestamp(sample, idx, total) {
    if (sample?.timestamp) return sample.timestamp;
    const { startMs, endMs } = selectedRangeDomain();
    const denominator = Math.max(total - 1, 1);
    return new Date(startMs + ((endMs - startMs) / denominator) * idx).toISOString();
}

function continuousTimelineSlots(rawPoints) {
    const slotCount = state.activeTrafficRange === "1h" || state.activeTrafficRange === "6h" ? 12 : 24;
    const endMs = Date.now();
    const startMs = endMs - rangeDurationMs();
    const slotMs = Math.max(1, (endMs - startMs) / slotCount);
    const slots = Array.from({ length: slotCount }, (_, idx) => ({
        timestamp: new Date(startMs + idx * slotMs).toISOString(),
        counts: { critical: 0, high: 0, medium: 0, low: 0 },
        total: 0
    }));

    rawPoints.forEach(point => {
        const timeMs = new Date(point.timestamp).getTime();
        if (!Number.isFinite(timeMs) || timeMs < startMs || timeMs > endMs) return;
        const idx = Math.min(slotCount - 1, Math.max(0, Math.floor((timeMs - startMs) / slotMs)));
        const counts = point.counts || {};
        slots[idx].counts.critical += counts.critical || 0;
        slots[idx].counts.high += counts.high || 0;
        slots[idx].counts.medium += counts.medium || 0;
        slots[idx].counts.low += counts.low || 0;
        slots[idx].total += point.total || 0;
    });

    return slots;
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
