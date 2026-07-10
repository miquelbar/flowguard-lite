import { state } from '../state.js';
import { formatBytes, formatNumber, formatTime } from '../utils/format.js';
import { activeRangeDurationMs, isDayRange } from '../utils/timeRanges.js';

function formatShortTime(date) {
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${hours}:${minutes}`;
}

function formatAxisTime(timestamp) {
    const date = new Date(timestamp);
    if (isDayRange()) {
        return date.toLocaleDateString([], { month: "short", day: "numeric" });
    }
    return formatShortTime(date);
}

function timeTicks(startTs, endTs) {
    const count = state.activeTrafficRange === "1h" ? 4 : 5;
    const step = (endTs - startTs) / (count - 1);
    return Array.from({ length: count }, (_, idx) => startTs + step * idx);
}

export function renderTrafficCharts(onRenderSignals) {
    const chartBytes = document.getElementById("traffic-chart-bytes");
    const chartPackets = document.getElementById("traffic-chart-packets");
    
    if (!chartBytes || !chartPackets) return;

    // Remove old event listeners by cloning nodes
    const newChartBytes = chartBytes.cloneNode(false);
    chartBytes.parentNode.replaceChild(newChartBytes, chartBytes);
    const newChartPackets = chartPackets.cloneNode(false);
    chartPackets.parentNode.replaceChild(newChartPackets, chartPackets);

    const cb = document.getElementById("traffic-chart-bytes");
    const cp = document.getElementById("traffic-chart-packets");

    const width = 900;
    const height = 220;
    const pad = { top: 14, right: 22, bottom: 46, left: 74 };
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;

    const data = state.trafficSeriesData || [];
    const points = data.map(item => ({
        ts: new Date(item.timestamp).getTime(),
        bytes: Number(item.bytes || 0),
        packets: Number(item.packets || 0),
        flows: Number(item.flows || 0),
    })).filter(item => Number.isFinite(item.ts));

    const bytesEmpty = document.getElementById("traffic-chart-bytes-empty");
    const packetsEmpty = document.getElementById("traffic-chart-packets-empty");

    if (bytesEmpty) bytesEmpty.classList.toggle("hidden", points.length > 0);
    if (packetsEmpty) packetsEmpty.classList.toggle("hidden", points.length > 0);

    if (points.length === 0) {
        cb.innerHTML = `<text x="${width / 2}" y="${height / 2}" text-anchor="middle" class="chart-muted">No data</text>`;
        cp.innerHTML = `<text x="${width / 2}" y="${height / 2}" text-anchor="middle" class="chart-muted">No data</text>`;
        if (onRenderSignals) onRenderSignals();
        return;
    }

    const maxTs = Date.now();
    const minTs = maxTs - activeRangeDurationMs();
    const tsSpan = Math.max(maxTs - minTs, 1);
    const xFor = ts => pad.left + ((ts - minTs) / tsSpan) * plotW;

    const xTickMarkup = timeTicks(minTs, maxTs).map((tick, idx, arr) => {
        const x = xFor(tick);
        const anchor = idx === 0 ? "start" : (idx === arr.length - 1 ? "end" : "middle");
        return `<line x1="${x.toFixed(2)}" y1="${pad.top}" x2="${x.toFixed(2)}" y2="${pad.top + plotH}" class="chart-grid chart-grid-vertical"></line>
            <text x="${x.toFixed(2)}" y="${height - 20}" text-anchor="${anchor}" class="chart-axis">${formatAxisTime(tick)}</text>`;
    }).join("");

    // ── Bytes Chart ────────────────────────────────────────────
    const maxBytes = Math.max(...points.map(p => p.bytes), 1);
    const yB = v => pad.top + plotH - (v / maxBytes) * plotH;

    const gridBytes = [0, 0.25, 0.5, 0.75, 1].map(frac => {
        const y = pad.top + plotH - (frac * plotH);
        return `<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" class="chart-grid"></line>
                <text x="${pad.left - 10}" y="${y + 4}" text-anchor="end" class="chart-axis">${formatBytes(maxBytes * frac)}</text>`;
    }).join("");

    const pathB = points.map((p, i) => `${i === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yB(p.bytes).toFixed(2)}`).join(" ");
    const areaB = `${pathB} L ${xFor(points[points.length-1].ts).toFixed(2)} ${pad.top+plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top+plotH} Z`;

    const anomalyMarkersB = (state.anomaliesData || []).map(anom => {
        const ts = new Date(anom.created_at).getTime();
        if (!Number.isFinite(ts) || ts < minTs || ts > maxTs) return "";
        const x = xFor(ts);
        const cls = anom.severity === "high" ? "chart-marker-high" : "chart-marker-medium";
        return `<line x1="${x}" y1="${pad.top}" x2="${x}" y2="${pad.top + plotH}" class="chart-marker ${cls}"></line>`;
    }).join("");

    cb.setAttribute("viewBox", `0 0 ${width} ${height}`);
    cb.innerHTML = `
        <defs>
            <linearGradient id="bytesAreaFill" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stop-color="#3f5f46" stop-opacity="0.22"></stop>
                <stop offset="100%" stop-color="#3f5f46" stop-opacity="0.02"></stop>
            </linearGradient>
        </defs>
        ${gridBytes}
        ${xTickMarkup}
        <path d="${areaB}" fill="url(#bytesAreaFill)"></path>
        <path d="${pathB}" class="chart-line" style="stroke:#3f5f46;"></path>
        ${anomalyMarkersB}
        ${points.map(p => `<circle cx="${xFor(p.ts).toFixed(2)}" cy="${yB(p.bytes).toFixed(2)}" r="${points.length===1?4.5:2.3}" class="chart-point" style="fill:#3f5f46;"></circle>`).join("")}
        <text x="${width / 2}" y="${height - 5}" text-anchor="middle" class="chart-axis">time</text>
        <line id="cb-crosshair" class="chart-crosshair" x1="-1" x2="-1" y1="${pad.top}" y2="${pad.top+plotH}" visibility="hidden"></line>
        <circle id="cb-dot" class="chart-hover-dot" cx="-100" cy="-100" r="4.5" style="fill:#3f5f46;" visibility="hidden"></circle>
    `;

    // ── Packets+Flows Chart ────────────────────────────────────
    const maxPackets = Math.max(...points.map(p => p.packets), 1);
    const maxFlows = Math.max(...points.map(p => p.flows), 1);
    const maxRate = Math.max(maxPackets, maxFlows);
    const yR = v => pad.top + plotH - (v / maxRate) * plotH;

    const gridPackets = [0, 0.25, 0.5, 0.75, 1].map(frac => {
        const y = pad.top + plotH - (frac * plotH);
        return `<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" class="chart-grid"></line>
                <text x="${pad.left - 10}" y="${y + 4}" text-anchor="end" class="chart-axis">${formatNumber(Math.round(maxRate * frac))}</text>`;
    }).join("");

    const pathP = points.map((p, i) => `${i === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yR(p.packets).toFixed(2)}`).join(" ");
    const areaP = `${pathP} L ${xFor(points[points.length-1].ts).toFixed(2)} ${pad.top+plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top+plotH} Z`;
    const pathF = points.map((p, i) => `${i === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yR(p.flows).toFixed(2)}`).join(" ");

    const anomalyMarkersP = (state.anomaliesData || []).map(anom => {
        const ts = new Date(anom.created_at).getTime();
        if (!Number.isFinite(ts) || ts < minTs || ts > maxTs) return "";
        const x = xFor(ts);
        const cls = anom.severity === "high" ? "chart-marker-high" : "chart-marker-medium";
        return `<line x1="${x}" y1="${pad.top}" x2="${x}" y2="${pad.top + plotH}" class="chart-marker ${cls}"></line>`;
    }).join("");

    cp.setAttribute("viewBox", `0 0 ${width} ${height}`);
    cp.innerHTML = `
        <defs>
            <linearGradient id="packetsAreaFill" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.18"></stop>
                <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.01"></stop>
            </linearGradient>
        </defs>
        ${gridPackets}
        ${xTickMarkup}
        <path d="${areaP}" fill="url(#packetsAreaFill)"></path>
        <path d="${pathP}" class="chart-line" style="stroke:#38bdf8;"></path>
        <path d="${pathF}" class="chart-line" style="stroke:#f59e0b; stroke-dasharray:4 2;"></path>
        ${anomalyMarkersP}
        ${points.map(p => `
            <circle cx="${xFor(p.ts).toFixed(2)}" cy="${yR(p.packets).toFixed(2)}" r="${points.length===1?4.5:2.3}" class="chart-point" style="fill:#38bdf8;"></circle>
            <circle cx="${xFor(p.ts).toFixed(2)}" cy="${yR(p.flows).toFixed(2)}" r="${points.length===1?4:2.3}" class="chart-point" style="fill:#f59e0b;"></circle>
        `).join("")}
        <text x="${width / 2}" y="${height - 5}" text-anchor="middle" class="chart-axis">time</text>
        <line id="cp-crosshair" class="chart-crosshair" x1="-1" x2="-1" y1="${pad.top}" y2="${pad.top+plotH}" visibility="hidden"></line>
        <circle id="cp-dot-p" class="chart-hover-dot" cx="-100" cy="-100" r="4.5" style="fill:#38bdf8;" visibility="hidden"></circle>
        <circle id="cp-dot-f" class="chart-hover-dot" cx="-100" cy="-100" r="4" style="fill:#f59e0b;" visibility="hidden"></circle>
    `;

    // ── Shared hover / tooltip logic ───────────────────────────
    const tooltip = document.getElementById("chart-tooltip");

    const cbCrosshair = document.getElementById("cb-crosshair");
    const cbDot       = document.getElementById("cb-dot");
    const cpCrosshair = document.getElementById("cp-crosshair");
    const cpDotP      = document.getElementById("cp-dot-p");
    const cpDotF      = document.getElementById("cp-dot-f");

    function hideAll() {
        [cbCrosshair, cbDot, cpCrosshair, cpDotP, cpDotF].forEach(el => {
            if (el) el.setAttribute("visibility", "hidden");
        });
        if (tooltip) tooltip.style.display = "none";
    }

    function onMove(e, svgEl) {
        const rect = svgEl.getBoundingClientRect();
        // Map client coords → SVG viewBox coords
        const mouseX = ((e.clientX - rect.left) / rect.width) * width;

        if (mouseX < pad.left || mouseX > width - pad.right) { hideAll(); return; }

        // Nearest point
        let nearest = null, minDist = Infinity;
        for (const p of points) {
            const d = Math.abs(xFor(p.ts) - mouseX);
            if (d < minDist) { minDist = d; nearest = p; }
        }
        if (!nearest) return;

        const x = xFor(nearest.ts).toFixed(2);

        // Update bytes chart
        if (cbCrosshair) { cbCrosshair.setAttribute("x1", x); cbCrosshair.setAttribute("x2", x); cbCrosshair.setAttribute("visibility", "visible"); }
        if (cbDot)       { cbDot.setAttribute("cx", x); cbDot.setAttribute("cy", yB(nearest.bytes).toFixed(2)); cbDot.setAttribute("visibility", "visible"); }

        // Update packets chart
        if (cpCrosshair) { cpCrosshair.setAttribute("x1", x); cpCrosshair.setAttribute("x2", x); cpCrosshair.setAttribute("visibility", "visible"); }
        if (cpDotP)      { cpDotP.setAttribute("cx", x); cpDotP.setAttribute("cy", yR(nearest.packets).toFixed(2)); cpDotP.setAttribute("visibility", "visible"); }
        if (cpDotF)      { cpDotF.setAttribute("cx", x); cpDotF.setAttribute("cy", yR(nearest.flows).toFixed(2)); cpDotF.setAttribute("visibility", "visible"); }

        // Tooltip
        if (tooltip) {
            tooltip.innerHTML = `
                <div style="font-weight:600;margin-bottom:0.3rem;">${formatTime(nearest.ts)}</div>
                <div style="display:flex;align-items:center;gap:0.5rem;">
                    <span style="width:8px;height:8px;border-radius:50%;background:#3f5f46;flex-shrink:0;display:inline-block;"></span>
                    <span>Bandwidth: <strong>${formatBytes(nearest.bytes)}</strong></span>
                </div>
                <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.2rem;">
                    <span style="width:8px;height:8px;border-radius:50%;background:#38bdf8;flex-shrink:0;display:inline-block;"></span>
                    <span>Packets: <strong>${formatNumber(nearest.packets)}</strong></span>
                </div>
                <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.2rem;">
                    <span style="width:8px;height:8px;border-radius:50%;background:#f59e0b;flex-shrink:0;display:inline-block;"></span>
                    <span>Flows: <strong>${formatNumber(nearest.flows)}</strong></span>
                </div>`;
            tooltip.style.display = "block";
            const tr = tooltip.getBoundingClientRect();
            let top  = e.clientY - tr.height / 2;
            let left = e.clientX + 18;
            if (left + tr.width + 5 > window.innerWidth) left = e.clientX - tr.width - 18;
            if (top < 4) top = 4;
            if (top + tr.height + 4 > window.innerHeight) top = window.innerHeight - tr.height - 4;
            tooltip.style.top  = `${top}px`;
            tooltip.style.left = `${left}px`;
        }
    }

    cb.addEventListener("mousemove", e => onMove(e, cb));
    cb.addEventListener("mouseleave", hideAll);
    cp.addEventListener("mousemove", e => onMove(e, cp));
    cp.addEventListener("mouseleave", hideAll);

    if (onRenderSignals) onRenderSignals();
}
