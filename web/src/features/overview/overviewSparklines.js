import { escapeHtml } from '../../lib/format.js';
import { activeRangeDurationMs, isDayRange } from '../../lib/timeRanges.js';

export function timeSparkline(points) {
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



export function timestampForHeatmapSlot(slot) {
    const { startMs, endMs } = selectedRangeDomain();
    return new Date(startMs + ((endMs - startMs) / 24) * slot).toISOString();
}



export function collectorTimestamp(sample, idx, total) {
    if (sample?.timestamp) return sample.timestamp;
    const { startMs, endMs } = selectedRangeDomain();
    const denominator = Math.max(total - 1, 1);
    return new Date(startMs + ((endMs - startMs) / denominator) * idx).toISOString();
}


