import { formatBytes, formatTime } from '../../lib/format.js';
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

export function drawDeviceTrafficChart(timeSeries) {
    const deviceChartContainer = document.getElementById("device-chart-container");
    if (!deviceChartContainer) return;
    const width = 360;
    const height = 120;
    const pad = { top: 10, right: 12, bottom: 22, left: 52 };
    const plot = chartPlot(width, height, pad);
    const plotH = plot.height;
    deviceChartContainer.innerHTML = "";
    const domain = selectedTimeDomain();

    const points = (timeSeries || []).map(item => ({
        ts: new Date(item.bucket_ts || item.timestamp).getTime(),
        value: Number(item.bytes || 0),
        raw: item
    })).filter(item => Number.isFinite(item.ts) && item.ts >= domain.startMs && item.ts <= domain.endMs);

    if (points.length === 0) {
        deviceChartContainer.innerHTML = `<span class="chart-empty-inline text-muted">No traffic data recorded in the selected range.</span>`;
        return;
    }

    const maxValue = Math.max(...points.map(p => p.value), 1);
    const xFor = createTimeScale(domain, width, pad);
    const yFor = createLinearScale(maxValue, height, pad);

    const gridLines = yGridMarkup(maxValue, width, height, pad, yFor, formatBytes, [0, 0.5, 1]);

    const pathData = points.map((p, idx) => `${idx === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yFor(p.value).toFixed(2)}`).join(" ");
    const areaData = `${pathData} L ${xFor(points[points.length - 1].ts).toFixed(2)} ${pad.top + plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top + plotH} Z`;
    const xTicks = timeTicks(domain.startMs, domain.endMs, 2).map((tick, idx) => {
        const x = xFor(tick);
        return `<text x="${x.toFixed(2)}" y="${height - 4}" text-anchor="${idx === 0 ? "start" : "end"}" class="chart-axis">${formatAxisTime(tick)}</text>`;
    }).join("");

    const svgContent = `
        <svg id="device-traffic-chart" class="device-traffic-chart" width="100%" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="Device traffic chart: selected range on X axis and bytes on Y axis">
            <defs>
                <linearGradient id="deviceAreaFill" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stop-color="var(--primary-color)" stop-opacity="0.15"></stop>
                    <stop offset="100%" stop-color="var(--primary-color)" stop-opacity="0.01"></stop>
                </linearGradient>
            </defs>
            ${gridLines}
            <path d="${areaData}" fill="url(#deviceAreaFill)"></path>
            <path d="${pathData}" class="chart-line" style="stroke: var(--primary-color); stroke-width: 1.5; fill: none;"></path>
            ${points.map(p => `<circle cx="${xFor(p.ts).toFixed(2)}" cy="${yFor(p.value).toFixed(2)}" r="2" class="chart-point" style="stroke: var(--primary-color);"></circle>`).join("")}
            ${xTicks}
            <line id="device-chart-crosshair" class="chart-crosshair" x1="-1" x2="-1" y1="${pad.top}" y2="${pad.top + plotH}" visibility="hidden"></line>
            <circle id="device-chart-dot" class="chart-hover-dot" cx="-100" cy="-100" r="4" visibility="hidden"></circle>
        </svg>
    `;
    deviceChartContainer.innerHTML = svgContent;
    applySelectedDomainAttributes(deviceChartContainer.querySelector("#device-traffic-chart"), domain);
    bindDeviceTrafficTooltip(deviceChartContainer, points, xFor, yFor, width, pad);
}

function bindDeviceTrafficTooltip(container, points, xFor, yFor, width, pad) {
    const svg = container.querySelector("#device-traffic-chart");
    const crosshair = container.querySelector("#device-chart-crosshair");
    const dot = container.querySelector("#device-chart-dot");
    if (!svg) return;

    const hide = () => {
        if (crosshair) crosshair.setAttribute("visibility", "hidden");
        if (dot) dot.setAttribute("visibility", "hidden");
        hideChartTooltip();
    };

    svg.addEventListener("mousemove", event => {
        const rect = svg.getBoundingClientRect();
        const mouseX = ((event.clientX - rect.left) / rect.width) * width;
        if (mouseX < pad.left || mouseX > width - pad.right) {
            hide();
            return;
        }
        let nearest = null;
        let distance = Infinity;
        points.forEach(point => {
            const current = Math.abs(xFor(point.ts) - mouseX);
            if (current < distance) {
                distance = current;
                nearest = point;
            }
        });
        if (!nearest) return;
        const x = xFor(nearest.ts).toFixed(2);
        if (crosshair) {
            crosshair.setAttribute("x1", x);
            crosshair.setAttribute("x2", x);
            crosshair.setAttribute("visibility", "visible");
        }
        if (dot) {
            dot.setAttribute("cx", x);
            dot.setAttribute("cy", yFor(nearest.value).toFixed(2));
            dot.setAttribute("visibility", "visible");
        }
        showChartTooltip(event, [
            tooltipTitle(formatTime(nearest.ts)),
            tooltipRow("Bytes", formatBytes(nearest.value), "var(--primary-color)")
        ].join(""));
    });
    svg.addEventListener("mouseleave", hide);
}
