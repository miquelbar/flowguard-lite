import { state } from '../state.js';
import { formatTime } from '../utils/format.js';
import * as api from '../api.js';
import { openFirewallModal } from './devices.js';
import { deviceIPCell } from '../utils/deviceLinks.js';

export function renderAnomalies() {
    const tblAnomalies = document.getElementById("tbl-anomalies").querySelector("tbody");
    if (!tblAnomalies) return;

    const searchQueryEl = document.getElementById("search-anomalies");
    const severityFilterEl = document.getElementById("filter-anomalies-severity");

    const searchQuery = searchQueryEl ? searchQueryEl.value.toLowerCase().trim() : "";
    const severityFilter = severityFilterEl ? severityFilterEl.value : "all";

    const filtered = (state.anomaliesData || []).filter(anom => {
        if (state.activeTriageFilter !== "all" && anom.status !== state.activeTriageFilter) return false;
        if (severityFilter !== "all" && anom.severity !== severityFilter) return false;
        if (searchQuery !== "") {
            const ipMatch = anom.ip.toLowerCase().includes(searchQuery);
            const typeMatch = anom.type.toLowerCase().includes(searchQuery);
            const descMatch = anom.description.toLowerCase().includes(searchQuery);
            if (!ipMatch && !typeMatch && !descMatch) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        tblAnomalies.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No anomalies match selection filters.</td></tr>`;
        return;
    }

    tblAnomalies.innerHTML = filtered.map(anom => {
        const badgeClass = anom.severity === "high" ? "badge-high" : (anom.severity === "medium" ? "badge-medium" : "badge-low");
        const statusClass = `status-${anom.status}`;
        const isSelected = state.selectedAnomalyId === anom.id.toString();
        
        return `
            <tr class="anomaly-row ${isSelected ? 'selected' : ''}" data-id="${anom.id}" style="cursor: pointer;">
                <td class="font-semibold">${deviceIPCell(anom.ip)}</td>
                <td><span class="badge ${badgeClass}">${anom.type}</span></td>
                <td style="text-transform: capitalize;"><span class="sev-dot sev-${anom.severity}"></span>${anom.severity}</td>
                <td>${formatTime(anom.created_at)}</td>
                <td><span class="${statusClass}">${anom.status}</span></td>
                <td class="text-center">
                    <button class="btn-secondary btn-select-anomaly" data-id="${anom.id}">Select</button>
                </td>
            </tr>
        `;
    }).join('');

    tblAnomalies.querySelectorAll("tr").forEach(row => {
        row.addEventListener("click", (e) => {
            if (e.target.tagName === "BUTTON" || e.target.tagName === "A") return;
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
    }

    if (anomalyDetailActions) {
        let buttonsHtml = "";
        if (anom.status === "active") {
            buttonsHtml = `
                <button class="btn-secondary btn-triage btn-ack" data-id="${anom.id}" data-action="acknowledged">Acknowledge</button>
                <button class="btn-secondary btn-triage btn-silence" data-id="${anom.id}" data-action="silenced">Silence</button>
                <button class="btn-secondary btn-block-rules" data-ip="${anom.ip}">Firewall Template</button>
            `;
        } else {
            buttonsHtml = `
                <button class="btn-secondary btn-triage btn-reactivate" data-id="${anom.id}" data-action="active">Reactivate</button>
                <button class="btn-secondary btn-block-rules" data-ip="${anom.ip}">Firewall Template</button>
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

        anomalyDetailActions.querySelectorAll(".btn-block-rules").forEach(btn => {
            btn.addEventListener("click", () => {
                openFirewallModal(anom.ip);
            });
        });
    }
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
    if (window.location.hash !== "#/alerts") {
        window.location.hash = "#/alerts";
    }
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
            triageFilters.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            state.activeTriageFilter = e.target.getAttribute("data-filter");
            renderAnomalies();
        });
    });

    const btnCloseDetails = document.getElementById("btn-close-anomaly-details");
    if (btnCloseDetails) {
        btnCloseDetails.addEventListener("click", closeAnomalyDetails);
    }
}
