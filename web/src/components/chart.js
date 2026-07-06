import { state } from '../state.js';
import { formatBytes, formatNumber, formatTime } from '../utils/format.js';

// Custom short time format helper for X axis
function formatShortTime(date) {
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${hours}:${minutes}`;
}

export function renderTrafficCharts(onRenderSignals) {
    const chartBytes = document.getElementById("traffic-chart-bytes");
    const chartPackets = document.getElementById("traffic-chart-packets");
    
    if (!chartBytes || !chartPackets) return;

    const width = 900;
    const height = 180;
    const pad = { top: 12, right: 22, bottom: 24, left: 74 };
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;

    const data = state.trafficSeriesData || [];
    const points = data.map(item => ({
        ts: new Date(item.timestamp).getTime(),
        bytes: Number(item.bytes || 0),
        packets: Number(item.packets || 0),
        flows: Number(item.flows || 0),
        raw: item
    })).filter(item => Number.isFinite(item.ts));

    const bytesEmpty = document.getElementById("traffic-chart-bytes-empty");
    const packetsEmpty = document.getElementById("traffic-chart-packets-empty");

    if (bytesEmpty) bytesEmpty.classList.toggle("hidden", points.length > 0);
    if (packetsEmpty) packetsEmpty.classList.toggle("hidden", points.length > 0);

    if (points.length === 0) {
        chartBytes.innerHTML = `<text x="${width / 2}" y="${height / 2}" text-anchor="middle" class="chart-muted">No data</text>`;
        chartPackets.innerHTML = `<text x="${width / 2}" y="${height / 2}" text-anchor="middle" class="chart-muted">No data</text>`;
        if (onRenderSignals) onRenderSignals();
        return;
    }

    const minTs = Math.min(...points.map(p => p.ts));
    const maxTs = Math.max(...points.map(p => p.ts));
    const tsSpan = Math.max(maxTs - minTs, 1);
    
    const xFor = ts => pad.left + ((ts - minTs) / tsSpan) * plotW;

    // 1. Render Bytes Chart
    const maxBytes = Math.max(...points.map(p => p.bytes), 1);
    const yForBytes = value => pad.top + plotH - (value / maxBytes) * plotH;
    
    const gridBytes = [0, 0.25, 0.5, 0.75, 1].map(frac => {
        const y = pad.top + plotH - (frac * plotH);
        const label = formatBytes(maxBytes * frac);
        return `<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" class="chart-grid"></line>
                <text x="${pad.left - 10}" y="${y + 4}" text-anchor="end" class="chart-axis">${label}</text>`;
    }).join("");

    const pathBytes = points.map((p, idx) => `${idx === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yForBytes(p.bytes).toFixed(2)}`).join(" ");
    const areaBytes = `${pathBytes} L ${xFor(points[points.length - 1].ts).toFixed(2)} ${pad.top + plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top + plotH} Z`;

    const firstLabel = formatShortTime(new Date(minTs));
    const lastLabel = formatShortTime(new Date(maxTs));
    const singleSampleGuide = points.length === 1
        ? `<line x1="${xFor(points[0].ts).toFixed(2)}" y1="${pad.top}" x2="${xFor(points[0].ts).toFixed(2)}" y2="${pad.top + plotH}" class="chart-sample-guide"></line>`
        : "";

    const anomalyMarkers = (state.anomaliesData || []).map(anom => {
        const ts = new Date(anom.created_at).getTime();
        if (!Number.isFinite(ts) || ts < minTs || ts > maxTs) return "";
        const x = xFor(ts);
        const colorClass = anom.severity === "high" ? "chart-marker-high" : "chart-marker-medium";
        return `<line x1="${x}" y1="${pad.top}" x2="${x}" y2="${pad.top + plotH}" class="chart-marker ${colorClass}"></line>`;
    }).join("");

    chartBytes.innerHTML = `
        <defs>
            <linearGradient id="bytesAreaFill" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stop-color="#3f5f46" stop-opacity="0.25"></stop>
                <stop offset="100%" stop-color="#3f5f46" stop-opacity="0.02"></stop>
            </linearGradient>
        </defs>
        ${gridBytes}
        <path d="${areaBytes}" class="chart-area" style="fill: url(#bytesAreaFill); color: #3f5f46;"></path>
        <path d="${pathBytes}" class="chart-line" style="stroke: #3f5f46;"></path>
        ${singleSampleGuide}
        ${points.map(p => `<circle cx="${xFor(p.ts).toFixed(2)}" cy="${yForBytes(p.bytes).toFixed(2)}" r="${points.length === 1 ? 4.5 : 2.3}" class="chart-point" style="fill: #3f5f46;"></circle>`).join("")}
        ${anomalyMarkers}
        <text x="${pad.left}" y="${height - 6}" class="chart-axis">${firstLabel}</text>
        <text x="${width - pad.right}" y="${height - 6}" text-anchor="end" class="chart-axis">${lastLabel}</text>
        <line id="chart-crosshair-bytes" class="chart-crosshair" y1="${pad.top}" y2="${pad.top + plotH}" x1="0" x2="0" style="display: none;"></line>
        <circle id="chart-hover-dot-bytes" r="4.5" class="chart-hover-dot" style="display: none; fill: #3f5f46;"></circle>
    `;

    // 2. Render Packets & Flows Chart
    const maxPackets = Math.max(...points.map(p => p.packets), 1);
    const maxFlows = Math.max(...points.map(p => p.flows), 1);
    const maxRate = Math.max(maxPackets, maxFlows);
    const yForRate = value => pad.top + plotH - (value / maxRate) * plotH;

    const gridPackets = [0, 0.25, 0.5, 0.75, 1].map(frac => {
        const y = pad.top + plotH - (frac * plotH);
        const label = formatNumber(Math.round(maxRate * frac));
        return `<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" class="chart-grid"></line>
                <text x="${pad.left - 10}" y="${y + 4}" text-anchor="end" class="chart-axis">${label}</text>`;
    }).join("");

    const pathPackets = points.map((p, idx) => `${idx === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yForRate(p.packets).toFixed(2)}`).join(" ");
    const areaPackets = `${pathPackets} L ${xFor(points[points.length - 1].ts).toFixed(2)} ${pad.top + plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top + plotH} Z`;

    const pathFlows = points.map((p, idx) => `${idx === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yForRate(p.flows).toFixed(2)}`).join(" ");

    chartPackets.innerHTML = `
        <defs>
            <linearGradient id="packetsAreaFill" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.20"></stop>
                <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.01"></stop>
            </linearGradient>
        </defs>
        ${gridPackets}
        <path d="${areaPackets}" class="chart-area" style="fill: url(#packetsAreaFill); color: #38bdf8;"></path>
        <path d="${pathPackets}" class="chart-line" style="stroke: #38bdf8;" title="Packets"></path>
        <path d="${pathFlows}" class="chart-line" style="stroke: #f59e0b; stroke-dasharray: 4 2;" title="Flows"></path>
        ${singleSampleGuide}
        ${points.map(p => `
            <circle cx="${xFor(p.ts).toFixed(2)}" cy="${yForRate(p.packets).toFixed(2)}" r="${points.length === 1 ? 4.5 : 2.3}" class="chart-point" style="fill: #38bdf8;"></circle>
            <circle cx="${xFor(p.ts).toFixed(2)}" cy="${yForRate(p.flows).toFixed(2)}" r="${points.length === 1 ? 4 : 2.3}" class="chart-point" style="fill: #f59e0b;"></circle>
        `).join("")}
        ${anomalyMarkers}
        <text x="${pad.left}" y="${height - 6}" class="chart-axis">${firstLabel}</text>
        <text x="${width - pad.right}" y="${height - 6}" text-anchor="end" class="chart-axis">${lastLabel}</text>
        <line id="chart-crosshair-packets" class="chart-crosshair" y1="${pad.top}" y2="${pad.top + plotH}" x1="0" x2="0" style="display: none;"></line>
        <circle id="chart-hover-dot-packets" r="4.5" class="chart-hover-dot" style="display: none; fill: #38bdf8;"></circle>
        <circle id="chart-hover-dot-flows" r="4" class="chart-hover-dot" style="display: none; fill: #f59e0b;"></circle>
    `;

    // 3. Synchronized Interactive Hover Handlers
    const crosshairBytes = document.getElementById("chart-crosshair-bytes");
    const hoverDotBytes = document.getElementById("chart-hover-dot-bytes");
    
    const crosshairPackets = document.getElementById("chart-crosshair-packets");
    const hoverDotPackets = document.getElementById("chart-hover-dot-packets");
    const hoverDotFlows = document.getElementById("chart-hover-dot-flows");

    const tooltip = document.getElementById("chart-tooltip");

    function hideTooltip() {
        if (crosshairBytes) crosshairBytes.style.display = "none";
        if (hoverDotBytes) hoverDotBytes.style.display = "none";
        if (crosshairPackets) crosshairPackets.style.display = "none";
        if (hoverDotPackets) hoverDotPackets.style.display = "none";
        if (hoverDotFlows) hoverDotFlows.style.display = "none";
        if (tooltip) tooltip.style.display = "none";
    }

    function handleMouseMove(e, targetChart) {
        const rect = targetChart.getBoundingClientRect();
        const mouseX = ((e.clientX - rect.left) / rect.width) * width;

        if (mouseX < pad.left || mouseX > width - pad.right) {
            hideTooltip();
            return;
        }

        // Find nearest point
        let nearest = null;
        let minDist = Infinity;
        for (const p of points) {
            const pX = xFor(p.ts);
            const dist = Math.abs(pX - mouseX);
            if (dist < minDist) {
                minDist = dist;
                nearest = p;
            }
        }

        if (nearest) {
            const x = xFor(nearest.ts).toFixed(2);
            
            // Positions crosshairs and dots
            if (crosshairBytes) {
                crosshairBytes.setAttribute("x1", x);
                crosshairBytes.setAttribute("x2", x);
                crosshairBytes.style.display = "block";
            }
            if (hoverDotBytes) {
                hoverDotBytes.setAttribute("cx", x);
                hoverDotBytes.setAttribute("cy", yForBytes(nearest.bytes).toFixed(2));
                hoverDotBytes.style.display = "block";
            }
            
            if (crosshairPackets) {
                crosshairPackets.setAttribute("x1", x);
                crosshairPackets.setAttribute("x2", x);
                crosshairPackets.style.display = "block";
            }
            if (hoverDotPackets) {
                hoverDotPackets.setAttribute("cx", x);
                hoverDotPackets.setAttribute("cy", yForRate(nearest.packets).toFixed(2));
                hoverDotPackets.style.display = "block";
            }
            if (hoverDotFlows) {
                hoverDotFlows.setAttribute("cx", x);
                hoverDotFlows.setAttribute("cy", yForRate(nearest.flows).toFixed(2));
                hoverDotFlows.style.display = "block";
            }

            if (tooltip) {
                const dateStr = formatTime(nearest.ts);
                tooltip.innerHTML = `
                    <div style="font-weight: 600; margin-bottom: 0.25rem;">${dateStr}</div>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #3f5f46;"></span>
                        <span>Bandwidth: <strong>${formatBytes(nearest.bytes)}</strong></span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.2rem;">
                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #38bdf8;"></span>
                        <span>Packets: <strong>${formatNumber(nearest.packets)}</strong></span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.2rem;">
                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #f59e0b;"></span>
                        <span>Flows: <strong>${formatNumber(nearest.flows)}</strong></span>
                    </div>
                `;
                
                // Position tooltip relative to client view, but bounding it inside viewport
                tooltip.style.display = "block";
                const toolRect = tooltip.getBoundingClientRect();
                
                // Position it 15px to the right and centered vertically
                let top = e.pageY - toolRect.height / 2;
                let left = e.pageX + 15;
                
                if (left + toolRect.width > window.innerWidth) {
                    left = e.pageX - toolRect.width - 15;
                }
                
                tooltip.style.top = `${top}px`;
                tooltip.style.left = `${left}px`;
            }
        }
    }

    chartBytes.addEventListener("mousemove", (e) => handleMouseMove(e, chartBytes));
    chartBytes.addEventListener("mouseleave", hideTooltip);

    chartPackets.addEventListener("mousemove", (e) => handleMouseMove(e, chartPackets));
    chartPackets.addEventListener("mouseleave", hideTooltip);

    if (onRenderSignals) onRenderSignals();
}
