import { state } from './state.js';
import { supportsGlobalTelemetryControls } from './viewRegistry.js';

let autoRefreshTimer = null;

export function scheduleAutoRefresh(viewName = state.activeView, refreshFn) {
    if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
        autoRefreshTimer = null;
    }

    const seconds = Number(state.autoRefreshSeconds || 0);
    if (!supportsGlobalTelemetryControls(viewName) || seconds <= 0 || typeof refreshFn !== "function") return;

    autoRefreshTimer = setInterval(() => {
        refreshFn(false);
    }, seconds * 1000);
}

export function stopAutoRefresh() {
    if (!autoRefreshTimer) return;
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
}

