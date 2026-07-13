import { state } from '../app/state.js';
import { availableTrafficRanges, setNormalizedTrafficRange } from '../lib/timeRanges.js';
import { supportsGlobalTelemetryControls } from '../app/viewRegistry.js';

export function syncGlobalRangeButtons(refreshFn) {
    setNormalizedTrafficRange();
    const container = document.getElementById("global-range-tabs");
    if (!container) return;
    const markup = availableTrafficRanges().map(range => `
        <button class="tab-btn global-range-btn${range.id === state.activeTrafficRange ? " active" : ""}" data-range="${range.id}" aria-label="Use ${range.label} time range" aria-pressed="${range.id === state.activeTrafficRange ? "true" : "false"}">${range.label}</button>
    `).join("");
    if (container.dataset.renderedRanges !== markup) {
        container.innerHTML = markup;
        container.dataset.renderedRanges = markup;
        bindGlobalRangeButtons(refreshFn);
        return;
    }
    container.querySelectorAll(".global-range-btn").forEach(btn => {
        const active = btn.getAttribute("data-range") === state.activeTrafficRange;
        btn.classList.toggle("active", active);
        btn.setAttribute("aria-pressed", active ? "true" : "false");
    });
}

export function bindGlobalRangeButtons(refreshFn) {
    document.querySelectorAll(".global-range-btn").forEach(btn => {
        if (btn.dataset.bound === "true") return;
        btn.dataset.bound = "true";
        btn.addEventListener("click", (e) => {
            state.activeTrafficRange = e.currentTarget.getAttribute("data-range");
            setNormalizedTrafficRange();
            syncGlobalRangeButtons(refreshFn);
            if (typeof refreshFn === "function") refreshFn(true);
        });
    });
}

export function syncGlobalRangeVisibility(viewName) {
    const globalTimeControl = document.querySelector(".global-time-control");
    const autoRefreshControl = document.querySelector(".auto-refresh-control");
    const show = supportsGlobalTelemetryControls(viewName);
    if (globalTimeControl) globalTimeControl.classList.toggle("hidden", !show);
    if (autoRefreshControl) autoRefreshControl.classList.toggle("hidden", !show);
}
