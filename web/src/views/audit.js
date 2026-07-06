import { state } from '../state.js';

export function renderAuditLogs() {
    const tblAuditLogs = document.getElementById("tbl-audit-logs");
    if (!tblAuditLogs) return;
    const tbody = tblAuditLogs.querySelector("tbody");
    if (!tbody) return;

    const searchAuditLogsEl = document.getElementById("search-audit-logs");
    const searchQuery = searchAuditLogsEl ? searchAuditLogsEl.value.toLowerCase().trim() : "";

    const filtered = (state.auditLogsData || []).filter(log => {
        if (searchQuery === "") return true;
        return log.action.toLowerCase().includes(searchQuery) || log.details.toLowerCase().includes(searchQuery);
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
        tbody.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No audit logs match filters.</td></tr>`;
        return;
    }

    tbody.innerHTML = pageData.map(log => `
        <tr>
            <td style="white-space: nowrap;">${new Date(log.timestamp).toLocaleString()}</td>
            <td><span class="badge badge-label">${log.action}</span></td>
            <td>${log.details}</td>
        </tr>
    `).join("");
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
