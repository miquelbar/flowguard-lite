import { state } from '../../app/state.js';
import { escapeHtml, formatNumber, formatTime } from '../../lib/format.js';
import {
    applySelectedDomainAttributes,
    chartPlot,
    createLinearScale,
    createTimeScale,
    formatAxisTime,
    hideChartTooltip,
    selectedTimeDomain,
    showChartTooltip,
    timeTicks,
    tooltipRow,
    tooltipTitle,
    yGridMarkup
} from '../../components/ui/chart.js';
import { errorState, overviewError, severityClass } from './overviewSupport.js';

export function renderAttackTimeline() {
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
    const plot = chartPlot(width, height, pad);
    const plotW = plot.width;
    const plotH = plot.height;
    const domain = selectedTimeDomain();
    const xForTime = createTimeScale(domain, width, pad);
    const yFor = createLinearScale(max, height, pad);
    const barGap = 4;
    const barW = Math.max(6, (plotW / points.length) - barGap);
    const yTicks = yGridMarkup(max, width, height, pad, yFor, value => formatNumber(Math.round(value)));
    const xTicks = timeTicks(domain.startMs, domain.endMs, points.length <= 12 ? 4 : 5).map((tick, idx, arr) => {
        const x = xForTime(tick);
        const anchor = idx === 0 ? "start" : (idx === arr.length - 1 ? "end" : "middle");
        return `<text x="${x.toFixed(2)}" y="${height - 12}" text-anchor="${anchor}" class="chart-axis">${escapeHtml(timelineTickLabel(tick))}</text>`;
    }).join("");
    const bars = points.map((point, idx) => {
        const counts = point.counts || {};
        const severity = counts.critical || counts.high ? "high" : (counts.medium ? "medium" : "low");
        const total = point.total || 0;
        const barH = total ? Math.max(3, (total / max) * plotH) : 2;
        const slotW = plotW / points.length;
        const x = xForTime(new Date(point.timestamp).getTime()) + ((slotW - barW) / 2);
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
    applySelectedDomainAttributes(el.querySelector(".attack-timeline-svg"), domain);
    bindAttackTimelineTooltips(el);
}



export function timelineTickLabel(timestamp) {
    const date = new Date(timestamp);
    return formatAxisTime(date.getTime());
}



export function bindAttackTimelineTooltips(root) {
    root.querySelectorAll(".attack-timeline-point").forEach(point => {
        point.addEventListener("mousemove", (e) => {
            const total = Number(point.dataset.total || 0);
            const critical = Number(point.dataset.critical || 0);
            const high = Number(point.dataset.high || 0);
            const medium = Number(point.dataset.medium || 0);
            const low = Number(point.dataset.low || 0);
            showChartTooltip(e, [
                tooltipTitle(formatTime(point.dataset.timestamp)),
                tooltipRow("Active alerts in bucket", formatNumber(total)),
                tooltipRow("Critical", formatNumber(critical)),
                tooltipRow("High", formatNumber(high)),
                tooltipRow("Medium", formatNumber(medium)),
                tooltipRow("Low", formatNumber(low))
            ].join(""));
        });
        point.addEventListener("mouseleave", hideChartTooltip);
    });
}



export function continuousTimelineSlots(rawPoints) {
    const slotCount = state.activeTrafficRange === "1h" || state.activeTrafficRange === "6h" ? 12 : 24;
    const { startMs, endMs } = selectedTimeDomain();
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
