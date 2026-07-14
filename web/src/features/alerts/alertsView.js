import { state } from '../../app/state.js';
import { formatTime, escapeHtml } from '../../lib/format.js';
import * as api from '../../lib/api.js';
import { openFirewallModal } from '../devices/firewallModal.js';
import { openPolicyModal } from '../policies/policyModal.js';
import { isKnownDeviceIP } from '../../lib/deviceLinks.js';
import { renderTableMessage } from '../../components/ui/states.js';
import { bindSplitPaneClose } from '../../components/layout/splitPane.js';
import { focusFirstVisibleOnMobile } from '../../components/ui/focus.js';
import { appendSearchToken, bindClickableFilters, captureClickableFilterFocus, restoreClickableFilterFocus, triggerEvent } from '../../lib/filter.js';

let lastFilterFocus = null;

export function renderAnomalies() {
    const tblAnomalies = document.getElementById("tbl-anomalies").querySelector("tbody");
    if (!tblAnomalies) return;

    if (state.anomaliesError) {
        tblAnomalies.innerHTML = renderTableMessage(6, "error", `Failed to load anomalies: ${state.anomaliesError}`);
        return;
    }

    const searchQueryEl = document.getElementById("search-anomalies");
    const severityFilterEl = document.getElementById("filter-anomalies-severity");

    const searchQuery = searchQueryEl ? searchQueryEl.value.toLowerCase().trim() : "";
    const severityFilter = severityFilterEl ? severityFilterEl.value : "all";

    const filtered = (state.anomaliesData || []).filter(anom => {
        if (state.activeTriageFilter !== "all" && anom.status !== state.activeTriageFilter) return false;
        if (severityFilter !== "all" && anom.severity !== severityFilter) return false;
        if (searchQuery !== "") {
            const tokens = searchQuery.split(/\s+/);
            const matchesAll = tokens.every(token => {
                return anom.ip.toLowerCase().includes(token) ||
                       anom.type.toLowerCase().includes(token) ||
                       anom.description.toLowerCase().includes(token) ||
                       anom.severity.toLowerCase().includes(token) ||
                       anom.status.toLowerCase().includes(token);
            });
            if (!matchesAll) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        tblAnomalies.innerHTML = renderTableMessage(6, "empty", "No anomalies match selection filters.");
        return;
    }

    tblAnomalies.innerHTML = filtered.map((anom, idx) => {
        const badgeClass = anom.severity === "high" ? "badge-high" : (anom.severity === "medium" ? "badge-medium" : "badge-low");
        const statusClass = `status-${anom.status}`;
        const isSelected = state.selectedAnomalyId === anom.id.toString();
        const ipSafe = escapeHtml(anom.ip || "-");
        const ipHtml = `<span tabindex="0" role="button" class="clickable-filter alert-filter-ip" data-val="${ipSafe}" data-col="ip" data-row-idx="${idx}" title="Click to filter by IP: ${ipSafe}">${ipSafe}</span>` +
            (anom.ip && isKnownDeviceIP(anom.ip) ? ` <a href="#/devices/${encodeURIComponent(anom.ip)}" class="device-profile-link" title="Go to Device Profile" aria-label="Go to Device Profile for ${ipSafe}">↗</a>` : "");
        const typeHtml = `<span tabindex="0" role="button" class="badge ${badgeClass} clickable-filter alert-filter-type" data-val="${escapeHtml(anom.type)}" data-col="type" data-row-idx="${idx}" title="Click to filter by Type: ${escapeHtml(anom.type)}">${escapeHtml(anom.type)}</span>`;
        const severityHtml = `<span tabindex="0" role="button" class="clickable-filter alert-filter-severity" data-val="${escapeHtml(anom.severity)}" data-col="severity" data-row-idx="${idx}" title="Click to filter by Severity: ${escapeHtml(anom.severity)}"><span class="sev-dot sev-${anom.severity}"></span>${escapeHtml(anom.severity)}</span>`;
        const statusHtml = `<span tabindex="0" role="button" class="clickable-filter alert-filter-status" data-val="${escapeHtml(anom.status)}" data-col="status" data-row-idx="${idx}" title="Click to filter by Status: ${escapeHtml(anom.status)}"><span class="${statusClass}">${escapeHtml(anom.status)}</span></span>`;
        
        return `
            <tr class="anomaly-row severity-${anom.severity} ${isSelected ? 'selected' : ''}" data-id="${anom.id}" style="cursor: pointer;">
                <td class="font-semibold">${ipHtml}</td>
                <td>${typeHtml}</td>
                <td style="text-transform: capitalize;">${severityHtml}</td>
                <td>${formatTime(anom.created_at)}</td>
                <td>${statusHtml}</td>
                <td class="text-center">
                    <button class="btn-secondary btn-select-anomaly" data-id="${anom.id}" aria-label="Select alert ${anom.id} for ${anom.ip}">Select</button>
                </td>
            </tr>
        `;
    }).join('');

    tblAnomalies.querySelectorAll("tr").forEach(row => {
        row.addEventListener("click", (e) => {
            if (e.target.tagName === "BUTTON" || e.target.tagName === "A" || e.target.closest(".clickable-filter")) return;
            const id = row.getAttribute("data-id");
            if (id) selectAnomaly(id);
        });
    });

    tblAnomalies.querySelectorAll(".btn-select-anomaly").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const id = e.target.getAttribute("data-id");
            selectAnomaly(id);
        });
    });

    bindClickableFilters(tblAnomalies, ({ col, val }) => {
        lastFilterFocus = captureClickableFilterFocus();
        if (col === "ip" || col === "type") {
            const searchInput = document.getElementById("search-anomalies");
            appendSearchToken(searchInput, val);
            triggerEvent(searchInput, "input");
        } else if (col === "severity") {
            const severitySelect = document.getElementById("filter-anomalies-severity");
            if (severitySelect) {
                severitySelect.value = val;
                triggerEvent(severitySelect, "change");
            }
        } else if (col === "status") {
            const btn = document.querySelector(`.triage-filter-btn[data-filter="${val}"]`);
            if (btn) btn.click();
        }
    });

    restoreClickableFilterFocus(tblAnomalies, lastFilterFocus);
    lastFilterFocus = null;
}

export function selectAnomaly(id) {
    state.selectedAnomalyId = id.toString();
    const nextHash = `#/alerts/${encodeURIComponent(id)}`;
    if (window.location.hash !== nextHash) {
        window.location.hash = nextHash;
    }
    renderAnomalies();

    const anomalyDetailsEmpty = document.getElementById("anomaly-details-empty");
    const anomalyDetailsContent = document.getElementById("anomaly-details-content");
    const anomalyDetailIp = document.getElementById("anomaly-detail-ip");
    const anomalyDetailType = document.getElementById("anomaly-detail-type");
    const anomalyDetailDescription = document.getElementById("anomaly-detail-description");
    const anomalyDetailTime = document.getElementById("anomaly-detail-time");
    const anomalyDetailStatus = document.getElementById("anomaly-detail-status");
    const anomalyDetailBadgeContainer = document.getElementById("anomaly-detail-badge-container");
    const anomalyDetailActions = document.getElementById("anomaly-detail-actions");

    const anom = state.anomaliesData.find(a => a.id.toString() === state.selectedAnomalyId);
    if (!anom) return;

    if (anomalyDetailsEmpty) anomalyDetailsEmpty.classList.add("hidden");
    if (anomalyDetailsContent) anomalyDetailsContent.classList.remove("hidden");

    if (anomalyDetailIp) anomalyDetailIp.textContent = anom.ip;
    if (anomalyDetailType) anomalyDetailType.textContent = anom.type;
    if (anomalyDetailDescription) anomalyDetailDescription.textContent = anom.description;
    if (anomalyDetailTime) anomalyDetailTime.textContent = new Date(anom.created_at).toLocaleString();
    if (anomalyDetailStatus) {
        anomalyDetailStatus.textContent = anom.status;
        anomalyDetailStatus.className = `badge-label status-${anom.status}`;
    }

    const badgeClass = anom.severity === "high" ? "badge-high" : (anom.severity === "medium" ? "badge-medium" : "badge-low");
    if (anomalyDetailBadgeContainer) {
        anomalyDetailBadgeContainer.innerHTML = `<span class="badge ${badgeClass}">${anom.severity.toUpperCase()}</span>`;
    }    if (anomalyDetailActions) {
        let buttonsHtml = "";
        if (anom.status === "active") {
            buttonsHtml = `
                <button class="btn-secondary btn-triage btn-ack" data-id="${anom.id}" data-action="acknowledged" aria-label="Acknowledge alert ${anom.id}">Acknowledge</button>
                <button class="btn-secondary btn-triage btn-silence" data-id="${anom.id}" data-action="silenced" aria-label="Silence alert ${anom.id}">Silence</button>
                <button class="btn-secondary btn-suppress-alert" data-id="${anom.id}" aria-label="Suppress alert ${anom.id}">Suppress Alert</button>
                <button class="btn-secondary btn-block-rules" data-ip="${anom.ip}" aria-label="Generate firewall template for ${anom.ip}">Firewall Template</button>
            `;
        } else {
            buttonsHtml = `
                <button class="btn-secondary btn-triage btn-reactivate" data-id="${anom.id}" data-action="active" aria-label="Reactivate alert ${anom.id}">Reactivate</button>
                <button class="btn-secondary btn-suppress-alert" data-id="${anom.id}" aria-label="Suppress alert ${anom.id}">Suppress Alert</button>
                <button class="btn-secondary btn-block-rules" data-ip="${anom.ip}" aria-label="Generate firewall template for ${anom.ip}">Firewall Template</button>
            `;
        }
        anomalyDetailActions.innerHTML = buttonsHtml;
 
        anomalyDetailActions.querySelectorAll(".btn-triage").forEach(btn => {
            btn.addEventListener("click", async (e) => {
                const action = btn.getAttribute("data-action");
                try {
                    await api.updateAnomalyStatus(anom.id, action);
                    window.showToast(`Alert status updated to ${action}.`);
                    state.anomaliesData = await api.fetchAnomalies();
                    state.riskDevicesData = await api.fetchThreatRisk();
                    selectAnomaly(anom.id);
                } catch (err) {
                    window.showToast(err.message, "error");
                }
            });
        });

        anomalyDetailActions.querySelectorAll(".btn-suppress-alert").forEach(btn => {
            btn.addEventListener("click", () => {
                openPolicyModal({ ip: anom.ip, category: anom.type });
            });
        });

        anomalyDetailActions.querySelectorAll(".btn-block-rules").forEach(btn => {
            btn.addEventListener("click", () => {
                openFirewallModal(anom.ip);
            });
        });
    }
    focusFirstVisibleOnMobile(["#btn-close-anomaly-details-floating", "#btn-close-anomaly-details"]);
}

export function renderAlertsView() {
    renderAnomalies();
    if (state.selectedAnomalyId) {
        selectAnomaly(state.selectedAnomalyId);
    } else {
        const anomalyDetailsEmpty = document.getElementById("anomaly-details-empty");
        const anomalyDetailsContent = document.getElementById("anomaly-details-content");
        if (anomalyDetailsEmpty) anomalyDetailsEmpty.classList.remove("hidden");
        if (anomalyDetailsContent) anomalyDetailsContent.classList.add("hidden");
    }
}

function closeAnomalyDetails() {
    state.selectedAnomalyId = null;
    const anomalyDetailsEmpty = document.getElementById("anomaly-details-empty");
    const anomalyDetailsContent = document.getElementById("anomaly-details-content");
    if (anomalyDetailsEmpty) anomalyDetailsEmpty.classList.remove("hidden");
    if (anomalyDetailsContent) anomalyDetailsContent.classList.add("hidden");
    renderAnomalies();
}

export function bindAlertsEvents() {
    const searchAnomalies = document.getElementById("search-anomalies");
    if (searchAnomalies) {
        searchAnomalies.addEventListener("input", () => {
            renderAnomalies();
        });
    }

    const filterSeverity = document.getElementById("filter-anomalies-severity");
    if (filterSeverity) {
        filterSeverity.addEventListener("change", () => {
            renderAnomalies();
        });
    }

    const triageFilters = document.querySelectorAll(".triage-filter-btn");
    triageFilters.forEach(btn => {
        btn.addEventListener("click", (e) => {
            triageFilters.forEach(b => {
                b.classList.remove("active");
                b.setAttribute("aria-pressed", "false");
            });
            e.target.classList.add("active");
            e.target.setAttribute("aria-pressed", "true");
            state.activeTriageFilter = e.target.getAttribute("data-filter");
            renderAnomalies();
        });
    });

    bindSplitPaneClose(
        ["btn-close-anomaly-details", "btn-close-anomaly-details-floating"],
        "#/alerts",
        closeAnomalyDetails,
        ["#search-anomalies"]
    );
}
