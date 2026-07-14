import { state } from '../../app/state.js';
import { renderTableMessage } from '../../components/ui/states.js';
import { appendSearchToken, bindClickableFilters, captureClickableFilterFocus, restoreClickableFilterFocus, triggerEvent } from '../../lib/filter.js';
import { escapeHtml } from '../../lib/format.js';

let lastFilterFocus = null;

export function renderAuditLogs() {
    const tblAuditLogs = document.getElementById("tbl-audit-logs");
    if (!tblAuditLogs) return;
    const tbody = tblAuditLogs.querySelector("tbody");
    if (!tbody) return;

    if (state.auditLogsError) {
        tbody.innerHTML = renderTableMessage(3, "error", `Failed to load audit logs: ${state.auditLogsError}`);
        return;
    }

    const searchAuditLogsEl = document.getElementById("search-audit-logs");
    const searchQuery = searchAuditLogsEl ? searchAuditLogsEl.value.toLowerCase().trim() : "";

    const filtered = (state.auditLogsData || []).filter(log => {
        if (searchQuery === "") return true;
        const tokens = searchQuery.split(/\s+/);
        return tokens.every(token => {
            return log.action.toLowerCase().includes(token) || log.details.toLowerCase().includes(token);
        });
    });

    const total = filtered.length;
    const totalPages = Math.ceil(total / state.auditLogPageSize) || 1;
    
    if (state.auditLogPage >= totalPages) {
        state.auditLogPage = totalPages - 1;
    }
    if (state.auditLogPage < 0) {
        state.auditLogPage = 0;
    }

    const startIdx = state.auditLogPage * state.auditLogPageSize;
    const endIdx = Math.min(startIdx + state.auditLogPageSize, total);
    const pageData = filtered.slice(startIdx, endIdx);

    const statsEl = document.getElementById("audit-pagination-stats");
    if (statsEl) {
        if (total === 0) {
            statsEl.textContent = "Showing 0-0 of 0 logs";
        } else {
            statsEl.textContent = `Showing ${startIdx + 1}-${endIdx} of ${total} logs`;
        }
    }

    const btnPrev = document.getElementById("btn-audit-prev");
    const btnNext = document.getElementById("btn-audit-next");
    if (btnPrev) btnPrev.disabled = (state.auditLogPage === 0);
    if (btnNext) btnNext.disabled = (state.auditLogPage >= totalPages - 1);

    if (pageData.length === 0) {
        tbody.innerHTML = renderTableMessage(3, "empty", "No audit logs match filters.");
        return;
    }

    tbody.innerHTML = pageData.map((log, idx) => `
        <tr>
            <td style="white-space: nowrap;">${new Date(log.timestamp).toLocaleString()}</td>
            <td><span tabindex="0" role="button" class="badge badge-label clickable-filter audit-filter-action" data-val="${escapeHtml(log.action)}" data-col="action" data-row-idx="${idx}" title="Click to filter by Action: ${escapeHtml(log.action)}">${escapeHtml(log.action)}</span></td>
            <td>${escapeHtml(log.details)}</td>
        </tr>
    `).join("");

    bindClickableFilters(tbody, ({ col, val }) => {
        lastFilterFocus = captureClickableFilterFocus();
        if (col === "action") {
            const searchInput = document.getElementById("search-audit-logs");
            appendSearchToken(searchInput, val);
            triggerEvent(searchInput, "input");
        }
    });

    restoreClickableFilterFocus(tbody, lastFilterFocus);
    lastFilterFocus = null;
}

export function renderAuditView() {
    renderAuditLogs();
}

export function bindAuditEvents() {
    const searchAuditLogs = document.getElementById("search-audit-logs");
    if (searchAuditLogs) {
        searchAuditLogs.addEventListener("input", () => {
            state.auditLogPage = 0;
            renderAuditLogs();
        });
    }

    const btnPrev = document.getElementById("btn-audit-prev");
    if (btnPrev) {
        btnPrev.addEventListener("click", () => {
            if (state.auditLogPage > 0) {
                state.auditLogPage--;
                renderAuditLogs();
            }
        });
    }

    const btnNext = document.getElementById("btn-audit-next");
    if (btnNext) {
        btnNext.addEventListener("click", () => {
            const searchAuditLogsEl = document.getElementById("search-audit-logs");
            const searchQuery = searchAuditLogsEl ? searchAuditLogsEl.value.toLowerCase().trim() : "";
            const filtered = (state.auditLogsData || []).filter(log => {
                if (searchQuery === "") return true;
                return log.action.toLowerCase().includes(searchQuery) || log.details.toLowerCase().includes(searchQuery);
            });
            const total = filtered.length;
            const totalPages = Math.ceil(total / state.auditLogPageSize) || 1;
            if (state.auditLogPage < totalPages - 1) {
                state.auditLogPage++;
                renderAuditLogs();
            }
        });
    }
}
