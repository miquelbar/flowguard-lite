import { escapeHtml } from '../../lib/format.js';

export function renderEmptyState(message) {
    return `<div class="text-center text-muted pad-large">${escapeHtml(message)}</div>`;
}

export function renderErrorState(message) {
    return `<div class="overview-error-state pad-large">${escapeHtml(message)}</div>`;
}

export function renderTableMessage(colSpan, type, message) {
    if (type === "error") {
        return `<tr><td colspan="${colSpan}"><div class="overview-error-state pad-large" style="margin: 1rem 0;">Failed to load data: ${escapeHtml(message)}</div></td></tr>`;
    }
    if (type === "empty") {
        return `<tr><td colspan="${colSpan}" class="text-center text-muted pad-large">${escapeHtml(message)}</td></tr>`;
    }
    if (type === "loading") {
        return `<tr><td colspan="${colSpan}" class="text-center text-muted pad-large">${escapeHtml(message || "Loading...")}</td></tr>`;
    }
    return "";
}
