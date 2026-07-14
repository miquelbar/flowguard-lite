import { state } from '../../app/state.js';
import { escapeHtml, formatBytes, formatNumber, formatTime } from '../../lib/format.js';
import { isKnownDeviceIP } from '../../lib/deviceLinks.js';
import { appendSearchToken, bindClickableFilters, captureClickableFilterFocus, restoreClickableFilterFocus, triggerEvent } from '../../lib/filter.js';

let lastFilterFocus = null;

function populateCollectorDropdown() {
    const select = document.getElementById("flow-explorer-collector");
    if (!select) return;

    const currentValue = select.value;
    const uniqueIds = new Set();
    if (state.trafficRecordsData) {
        state.trafficRecordsData.forEach(r => {
            if (r.collector_id) uniqueIds.add(r.collector_id);
        });
    }

    let html = `<option value="">All Collectors</option>`;
    Array.from(uniqueIds).sort().forEach(id => {
        html += `<option value="${escapeHtml(id)}">${escapeHtml(id)}</option>`;
    });

    select.innerHTML = html;
    select.value = uniqueIds.has(currentValue) ? currentValue : "";
}

function renderIPCellWithFilter(ip, filterClass, rowIdx, dir) {
    const safe = escapeHtml(ip || "-");
    const filterHtml = `<span tabindex="0" role="button" class="clickable-filter ${filterClass}" data-val="${safe}" data-col="${dir}-ip" data-row-idx="${rowIdx}" title="Click to filter by IP: ${safe}">${safe}</span>`;
    if (ip && isKnownDeviceIP(ip)) {
        return `${filterHtml} <a href="#/devices/${encodeURIComponent(ip)}" class="device-profile-link" title="Go to Device Profile" aria-label="Go to Device Profile for ${safe}">↗</a>`;
    }
    return filterHtml;
}

export function renderFlowExplorer() {
    const body = document.querySelector("#tbl-flow-explorer tbody");
    if (!body) return;

    syncFlowExplorerSortHeaders();
    populateCollectorDropdown();

    let rows = state.trafficRecordsData || [];
    const collectorFilter = document.getElementById("flow-explorer-collector");
    if (collectorFilter && collectorFilter.value) {
        rows = rows.filter(r => r.collector_id === collectorFilter.value);
    }

    rows = sortFlowExplorerRows(rows);
    if (rows.length === 0) {
        body.innerHTML = `<tr><td colspan="9" class="text-center text-muted">No aggregate records match the active filters.</td></tr>`;
        return;
    }

    body.innerHTML = rows.map((row, idx) => {
        const protocolHtml = `<span tabindex="0" role="button" class="clickable-filter flow-filter-protocol" data-val="${row.protocol}" data-col="protocol" data-row-idx="${idx}" title="Click to filter by Protocol: ${row.protocol}">${formatNumber(row.protocol || 0)}</span>`;
        const portHtml = `<span tabindex="0" role="button" class="clickable-filter flow-filter-port" data-val="${row.dst_port}" data-col="port" data-row-idx="${idx}" title="Click to filter by Destination Port: ${row.dst_port}">${formatNumber(row.dst_port || 0)}</span>`;
        return `
            <tr>
                <td class="font-mono text-muted">${formatTime(row.timestamp)}</td>
                <td>${collectorSourceCell(row, idx)}</td>
                <td>${renderIPCellWithFilter(row.src_ip, "flow-filter-ip", idx, "src")}</td>
                <td>${renderIPCellWithFilter(row.dst_ip, "flow-filter-ip", idx, "dst")}</td>
                <td class="text-right">${protocolHtml}</td>
                <td class="text-right">${portHtml}</td>
                <td class="text-right">${formatNumber(row.flows || 0)}</td>
                <td class="text-right">${formatNumber(row.packets || 0)}</td>
                <td class="text-right">${formatBytes(row.bytes || 0)}</td>
            </tr>
        `;
    }).join("");

    bindClickableFilters(body, handleFlowExplorerFilter);
    restoreClickableFilterFocus(body, lastFilterFocus);
    lastFilterFocus = null;
}

function handleFlowExplorerFilter({ col, val }) {
    lastFilterFocus = captureClickableFilterFocus();
    if (col === "src-ip" || col === "dst-ip") {
        const searchInput = document.getElementById("flow-explorer-search");
        appendSearchToken(searchInput, val);
        document.getElementById("btn-flow-explorer-search")?.click();
    } else if (col === "protocol") {
        setExplorerInputAndSearch("flow-explorer-protocol", val);
    } else if (col === "port") {
        setExplorerInputAndSearch("flow-explorer-port", val);
    } else if (col === "collector") {
        const collectorSelect = document.getElementById("flow-explorer-collector");
        if (collectorSelect) {
            collectorSelect.value = val;
            triggerEvent(collectorSelect, "change");
        }
    }
}

function setExplorerInputAndSearch(id, value) {
    const input = document.getElementById(id);
    if (!input) return;
    input.value = value;
    document.getElementById("btn-flow-explorer-search")?.click();
}

function collectorSourceCell(row, rowIdx) {
    const kind = row.collector_kind || "unknown";
    const id = row.collector_id || "unknown";
    return `<span tabindex="0" role="button" class="badge badge-label clickable-filter flow-filter-collector" data-val="${escapeHtml(id)}" data-col="collector" data-row-idx="${rowIdx}" title="Click to filter by collector: ${escapeHtml(kind)}">${escapeHtml(id)}</span>`;
}

function sortFlowExplorerRows(rows) {
    const sort = state.trafficRecordSort || { key: "timestamp", direction: "desc" };
    const key = sort.key || "timestamp";
    const multiplier = sort.direction === "asc" ? 1 : -1;
    const numericKeys = new Set(["protocol", "dst_port", "flows", "packets", "bytes"]);
    return [...rows].sort((a, b) => {
        let av = a[key];
        let bv = b[key];
        if (key === "timestamp") {
            av = new Date(av).getTime();
            bv = new Date(bv).getTime();
        } else if (numericKeys.has(key)) {
            av = Number(av || 0);
            bv = Number(bv || 0);
        } else {
            av = String(av || "");
            bv = String(bv || "");
            return av.localeCompare(bv, undefined, { numeric: true, sensitivity: "base" }) * multiplier;
        }
        if (av < bv) return -1 * multiplier;
        if (av > bv) return 1 * multiplier;
        return 0;
    });
}

export function syncFlowExplorerSortHeaders() {
    const sort = state.trafficRecordSort || { key: "timestamp", direction: "desc" };
    document.querySelectorAll("[data-flow-sort]").forEach(btn => {
        const isActive = btn.getAttribute("data-flow-sort") === sort.key;
        btn.classList.toggle("active", isActive);
        const th = btn.closest("th");
        if (th) th.setAttribute("aria-sort", isActive ? (sort.direction === "asc" ? "ascending" : "descending") : "none");
        const baseLabel = btn.textContent.replace(/[▲▼]/g, "").trim();
        btn.setAttribute("aria-label", isActive
            ? `Sort flow explorer by ${baseLabel}, currently ${sort.direction === "asc" ? "ascending" : "descending"}`
            : `Sort flow explorer by ${baseLabel}`);
        const indicator = btn.querySelector(".sort-indicator");
        if (indicator) indicator.textContent = isActive ? (sort.direction === "asc" ? "▲" : "▼") : "";
    });
}
