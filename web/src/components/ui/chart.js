import { state } from '../../app/state.js';
import { escapeHtml, formatBytes, formatNumber, formatTime } from '../../lib/format.js';
import { activeRangeDurationMs, isDayRange } from '../../lib/timeRanges.js';

export function selectedTimeDomain(nowMs = Date.now()) {
    return {
        startMs: nowMs - activeRangeDurationMs(),
        endMs: nowMs
    };
}

export function applySelectedDomainAttributes(svg, domain = selectedTimeDomain()) {
    if (!svg) return;
    svg.setAttribute("data-x-domain", "selected-range");
    svg.setAttribute("data-domain-start", new Date(domain.startMs).toISOString());
    svg.setAttribute("data-domain-end", new Date(domain.endMs).toISOString());
}

export function chartPlot(width, height, pad) {
    return {
        width: width - pad.left - pad.right,
        height: height - pad.top - pad.bottom
    };
}

export function createTimeScale(domain, width, pad) {
    const span = Math.max(domain.endMs - domain.startMs, 1);
    return timestamp => pad.left + ((timestamp - domain.startMs) / span) * (width - pad.left - pad.right);
}

export function createLinearScale(maxValue, height, pad) {
    const plotH = height - pad.top - pad.bottom;
    const safeMax = Math.max(Number(maxValue || 0), 1);
    return value => pad.top + plotH - (Number(value || 0) / safeMax) * plotH;
}

export function formatShortAxisTime(date) {
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${hours}:${minutes}`;
}

export function formatAxisTime(timestamp) {
    const date = new Date(timestamp);
    if (isDayRange()) {
        return date.toLocaleDateString([], { month: "short", day: "numeric" });
    }
    return formatShortAxisTime(date);
}

export function timeTicks(startTs, endTs, count = axisTickCount()) {
    if (count <= 1) return [startTs];
    const step = (endTs - startTs) / (count - 1);
    return Array.from({ length: count }, (_, idx) => startTs + step * idx);
}

export function xAxisTimeMarkup(domain, width, height, pad, xFor, tickCount = axisTickCount()) {
    return timeTicks(domain.startMs, domain.endMs, tickCount).map((tick, idx, arr) => {
        const x = xFor(tick);
        const anchor = idx === 0 ? "start" : (idx === arr.length - 1 ? "end" : "middle");
        return `<line x1="${x.toFixed(2)}" y1="${pad.top}" x2="${x.toFixed(2)}" y2="${height - pad.bottom}" class="chart-grid chart-grid-vertical"></line>
            <text x="${x.toFixed(2)}" y="${height - 20}" text-anchor="${anchor}" class="chart-axis">${escapeHtml(formatAxisTime(tick))}</text>`;
    }).join("");
}

export function yGridMarkup(maxValue, width, height, pad, yFor, formatter, fractions = [0, 0.25, 0.5, 0.75, 1]) {
    return fractions.map(frac => {
        const value = maxValue * frac;
        const y = yFor(value);
        return `<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" class="chart-grid"></line>
            <text x="${pad.left - 10}" y="${y + 4}" text-anchor="end" class="chart-axis">${escapeHtml(formatter(value))}</text>`;
    }).join("");
}

export function setChartEmpty(svg, emptyEl, isEmpty, message = "No data", width = 900, height = 220) {
    if (emptyEl) {
        emptyEl.classList.toggle("hidden", !isEmpty);
        emptyEl.textContent = message;
    }
    if (isEmpty && svg) {
        svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
        svg.innerHTML = `<text x="${width / 2}" y="${height / 2}" text-anchor="middle" class="chart-muted">${escapeHtml(message)}</text>`;
    }
}

export function hideChartTooltip() {
    const tooltip = document.getElementById("chart-tooltip");
    if (tooltip) tooltip.style.display = "none";
}

export function showChartTooltip(event, content) {
    const tooltip = document.getElementById("chart-tooltip");
    if (!tooltip) return;
    tooltip.setAttribute("role", "status");
    tooltip.innerHTML = content;
    tooltip.style.display = "block";
    const rect = tooltip.getBoundingClientRect();
    let top = event.clientY - rect.height / 2;
    let left = event.clientX + 18;
    if (left + rect.width + 8 > window.innerWidth) left = event.clientX - rect.width - 18;
    if (top < 8) top = 8;
    if (top + rect.height + 8 > window.innerHeight) top = window.innerHeight - rect.height - 8;
    tooltip.style.top = `${top}px`;
    tooltip.style.left = `${left}px`;
}

export function tooltipTitle(value) {
    return `<div class="chart-tooltip-title">${escapeHtml(String(value || ""))}</div>`;
}

export function tooltipRow(label, value, color = "") {
    const dot = color ? `<span class="chart-tooltip-dot" style="background:${escapeHtml(color)};"></span>` : "";
    return `<div class="chart-tooltip-row">
        ${dot}
        <span>${escapeHtml(label)}: <strong>${escapeHtml(String(value))}</strong></span>
    </div>`;
}

function axisTickCount() {
    return state.activeTrafficRange === "1h" ? 4 : 5;
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
    const plot = chartPlot(width, height, pad);
    const plotH = plot.height;

    const data = state.trafficSeriesData || [];
    const points = data.map(item => ({
        ts: new Date(item.timestamp).getTime(),
        bytes: Number(item.bytes || 0),
        packets: Number(item.packets || 0),
        flows: Number(item.flows || 0),
    })).filter(item => Number.isFinite(item.ts));

    const bytesEmpty = document.getElementById("traffic-chart-bytes-empty");
    const packetsEmpty = document.getElementById("traffic-chart-packets-empty");
    const domain = selectedTimeDomain();
    applySelectedDomainAttributes(cb, domain);
    applySelectedDomainAttributes(cp, domain);

    if (points.length === 0) {
        setChartEmpty(cb, bytesEmpty, true, "No traffic data.", width, height);
        setChartEmpty(cp, packetsEmpty, true, "No traffic data.", width, height);
        if (onRenderSignals) onRenderSignals();
        return;
    }
    setChartEmpty(cb, bytesEmpty, false);
    setChartEmpty(cp, packetsEmpty, false);

    const minTs = domain.startMs;
    const maxTs = domain.endMs;
    const xFor = createTimeScale(domain, width, pad);
    const xTickMarkup = xAxisTimeMarkup(domain, width, height, pad, xFor);

    // ── Bytes Chart ────────────────────────────────────────────
    const maxBytes = Math.max(...points.map(p => p.bytes), 1);
    const yB = createLinearScale(maxBytes, height, pad);
    const gridBytes = yGridMarkup(maxBytes, width, height, pad, yB, formatBytes);

    const pathB = points.map((p, i) => `${i === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yB(p.bytes).toFixed(2)}`).join(" ");
    const areaB = `${pathB} L ${xFor(points[points.length-1].ts).toFixed(2)} ${pad.top+plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top+plotH} Z`;

    const anomalyMarkersB = (state.anomaliesData || []).map(anom => {
        const ts = new Date(anom.detected_at || anom.created_at).getTime();
        if (!Number.isFinite(ts) || ts < minTs || ts > maxTs) return "";
        const x = xFor(ts);
        const cls = anom.severity === "high" ? "chart-marker-high" : "chart-marker-medium";
        return `<line x1="${x}" y1="${pad.top}" x2="${x}" y2="${pad.top + plotH}" class="chart-marker ${cls}"></line>`;
    }).join("");

    cb.setAttribute("viewBox", `0 0 ${width} ${height}`);
    applySelectedDomainAttributes(cb, domain);
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
    const yR = createLinearScale(maxRate, height, pad);
    const gridPackets = yGridMarkup(maxRate, width, height, pad, yR, value => formatNumber(Math.round(value)));

    const pathP = points.map((p, i) => `${i === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yR(p.packets).toFixed(2)}`).join(" ");
    const areaP = `${pathP} L ${xFor(points[points.length-1].ts).toFixed(2)} ${pad.top+plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top+plotH} Z`;
    const pathF = points.map((p, i) => `${i === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yR(p.flows).toFixed(2)}`).join(" ");

    const anomalyMarkersP = (state.anomaliesData || []).map(anom => {
        const ts = new Date(anom.detected_at || anom.created_at).getTime();
        if (!Number.isFinite(ts) || ts < minTs || ts > maxTs) return "";
        const x = xFor(ts);
        const cls = anom.severity === "high" ? "chart-marker-high" : "chart-marker-medium";
        return `<line x1="${x}" y1="${pad.top}" x2="${x}" y2="${pad.top + plotH}" class="chart-marker ${cls}"></line>`;
    }).join("");

    cp.setAttribute("viewBox", `0 0 ${width} ${height}`);
    applySelectedDomainAttributes(cp, domain);
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

    const cbCrosshair = document.getElementById("cb-crosshair");
    const cbDot       = document.getElementById("cb-dot");
    const cpCrosshair = document.getElementById("cp-crosshair");
    const cpDotP      = document.getElementById("cp-dot-p");
    const cpDotF      = document.getElementById("cp-dot-f");

    function hideAll() {
        [cbCrosshair, cbDot, cpCrosshair, cpDotP, cpDotF].forEach(el => {
            if (el) el.setAttribute("visibility", "hidden");
        });
        hideChartTooltip();
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
        showChartTooltip(e, [
            tooltipTitle(formatTime(nearest.ts)),
            tooltipRow("Bandwidth", formatBytes(nearest.bytes), "#3f5f46"),
            tooltipRow("Packets", formatNumber(nearest.packets), "#38bdf8"),
            tooltipRow("Flows", formatNumber(nearest.flows), "#f59e0b")
        ].join(""));
    }

    cb.addEventListener("mousemove", e => onMove(e, cb));
    cb.addEventListener("mouseleave", hideAll);
    cp.addEventListener("mousemove", e => onMove(e, cp));
    cp.addEventListener("mouseleave", hideAll);

    if (onRenderSignals) onRenderSignals();
}
