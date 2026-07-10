import { state } from '../state.js';
import { escapeHtml } from './format.js';

export function isKnownDeviceIP(ip) {
    return (state.devicesData || []).some(device => device.ip === ip);
}

export function deviceIPCell(ip, className = "ip-link") {
    const safe = escapeHtml(ip || "-");
    if (!ip || !isKnownDeviceIP(ip)) {
        return `<span class="text-muted font-mono" title="External or undiscovered IP; no local device profile exists.">${safe}</span>`;
    }
    return `<a href="#/devices/${encodeURIComponent(ip)}" class="${className}">${safe}</a>`;
}

export function deviceHref(ip) {
    return isKnownDeviceIP(ip) ? `#/devices/${encodeURIComponent(ip)}` : "";
}
