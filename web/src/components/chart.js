import { state } from '../state.js';
import { formatBytes, formatNumber, formatTime, formatShortTime } from '../utils/format.js';

export function renderTrafficChart(onRenderSignals) {
    const trafficChart = document.getElementById("traffic-chart");
    const trafficChartEmpty = document.getElementById("traffic-chart-empty");
    if (!trafficChart) return;
    
    const width = 900;
    const height = 260;
    const pad = { top: 18, right: 22, bottom: 32, left: 74 };
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;
    trafficChart.innerHTML = "";

    const points = (state.trafficSeriesData || []).map(item => ({
        ts: new Date(item.timestamp).getTime(),
        value: Number(item[state.activeTrafficMetric] || 0),
        raw: item
    })).filter(item => Number.isFinite(item.ts));

    if (trafficChartEmpty) trafficChartEmpty.classList.toggle("hidden", points.length > 0);
    if (points.length === 0) {
        trafficChart.innerHTML = `<text x="${width / 2}" y="${height / 2}" text-anchor="middle" class="chart-muted">No data</text>`;
        if (onRenderSignals) onRenderSignals();
        return;
    }

    const minTs = Math.min(...points.map(p => p.ts));
    const maxTs = Math.max(...points.map(p => p.ts));
    const maxValue = Math.max(...points.map(p => p.value), 1);
    const tsSpan = Math.max(maxTs - minTs, 1);
    const xFor = ts => pad.left + ((ts - minTs) / tsSpan) * plotW;
    const yFor = value => pad.top + plotH - (value / maxValue) * plotH;

    const gridLines = [0, 0.25, 0.5, 0.75, 1].map(frac => {
        const y = pad.top + plotH - (frac * plotH);
        const label = state.activeTrafficMetric === "bytes" ? formatBytes(maxValue * frac) : formatNumber(Math.round(maxValue * frac));
        return `<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" class="chart-grid"></line>
                <text x="${pad.left - 10}" y="${y + 4}" text-anchor="end" class="chart-axis">${label}</text>`;
    }).join("");

    const pathData = points.map((p, idx) => `${idx === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yFor(p.value).toFixed(2)}`).join(" ");
    const areaData = `${pathData} L ${xFor(points[points.length - 1].ts).toFixed(2)} ${pad.top + plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top + plotH} Z`;
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

    trafficChart.innerHTML = `
        <defs>
            <linearGradient id="trafficAreaFill" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stop-color="currentColor" stop-opacity="0.20"></stop>
                <stop offset="100%" stop-color="currentColor" stop-opacity="0.02"></stop>
            </linearGradient>
        </defs>
        ${gridLines}
        <path d="${areaData}" class="chart-area"></path>
        <path d="${pathData}" class="chart-line"></path>
        ${singleSampleGuide}
        ${points.map(p => `<circle cx="${xFor(p.ts).toFixed(2)}" cy="${yFor(p.value).toFixed(2)}" r="${points.length === 1 ? 4.5 : 2.3}" class="chart-point"></circle>`).join("")}
        ${anomalyMarkers}
        <text x="${pad.left}" y="${height - 8}" class="chart-axis">${firstLabel}</text>
        <text x="${width - pad.right}" y="${height - 8}" text-anchor="end" class="chart-axis">${lastLabel}</text>
        <line id="chart-crosshair" class="chart-crosshair" y1="${pad.top}" y2="${pad.top + plotH}" x1="0" x2="0" style="display: none;"></line>
        <circle id="chart-hover-dot" r="4.5" class="chart-hover-dot" style="display: none;"></circle>
    `;

    const crosshair = document.getElementById("chart-crosshair");
    const hoverDot = document.getElementById("chart-hover-dot");
    const tooltip = document.getElementById("chart-tooltip");

    if (crosshair && hoverDot && tooltip) {
        const onMouseMove = (e) => {
            const rect = trafficChart.getBoundingClientRect();
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
                const nx = xFor(nearest.ts);
                const ny = yFor(nearest.value);

                // Position SVG elements
                crosshair.setAttribute("x1", nx);
                crosshair.setAttribute("x2", nx);
                crosshair.style.display = "block";

                hoverDot.setAttribute("cx", nx);
                hoverDot.setAttribute("cy", ny);
                hoverDot.style.display = "block";

                // Formulate tooltip content
                const timeStr = formatTime(new Date(nearest.ts));
                const valFormatted = state.activeTrafficMetric === "bytes" ? formatBytes(nearest.value) : formatNumber(nearest.value);
                
                // Check if there are anomalies close to this timestamp (within 30 mins)
                let anomalyInfo = "";
                const nearbyAnoms = (state.anomaliesData || []).filter(anom => {
                    const anomTs = new Date(anom.created_at).getTime();
                    return Math.abs(anomTs - nearest.ts) <= 30 * 60 * 1000;
                });
                if (nearbyAnoms.length > 0) {
                    anomalyInfo = `<div style="margin-top: 0.25rem; border-top: 1px solid var(--border-color); padding-top: 0.25rem; color: var(--danger-color); font-weight: bold;">
                        ⚠️ Anomaly: ${nearbyAnoms[0].type} (${nearbyAnoms[0].ip})
                    </div>`;
                }

                tooltip.innerHTML = `
                    <div><strong>Time:</strong> ${timeStr}</div>
                    <div><strong>${state.activeTrafficMetric.charAt(0).toUpperCase() + state.activeTrafficMetric.slice(1)}:</strong> ${valFormatted}</div>
                    ${anomalyInfo}
                `;

                // Calculate absolute position of tooltip relative to the traffic-chart-frame
                const tooltipW = tooltip.offsetWidth || 150;
                const tooltipH = tooltip.offsetHeight || 60;
                
                // Scale coordinates back to client/pixel space relative to parent
                const pixelX = ((nx) / width) * rect.width;
                const pixelY = ((ny) / height) * rect.height;

                let left = pixelX + 15;
                let top = pixelY - tooltipH / 2;

                // Keep tooltip within frame boundaries
                if (left + tooltipW > rect.width) {
                    left = pixelX - tooltipW - 15;
                }
                if (top < 0) {
                    top = 10;
                }
                if (top + tooltipH > rect.height) {
                    top = rect.height - tooltipH - 10;
                }

                tooltip.style.left = `${left}px`;
                tooltip.style.top = `${top}px`;
                tooltip.style.display = "block";
                tooltip.style.opacity = "1";
            } else {
                hideTooltip();
            }
        };

        const hideTooltip = () => {
            crosshair.style.display = "none";
            hoverDot.style.display = "none";
            tooltip.style.display = "none";
            tooltip.style.opacity = "0";
        };

        trafficChart.addEventListener("mousemove", onMouseMove);
        trafficChart.addEventListener("mouseleave", hideTooltip);
    }

    if (onRenderSignals) onRenderSignals();
}
