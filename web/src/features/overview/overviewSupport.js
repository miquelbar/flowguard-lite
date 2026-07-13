import { state } from '../../app/state.js';
import { renderEmptyState, renderErrorState } from '../../components/ui/states.js';

export function severityClass(severity) {
    if (severity === "critical" || severity === "high") return "badge-high";
    if (severity === "medium") return "badge-medium";
    return "badge-low";
}

export function riskClass(level, score) {
    if (level === "high" || score >= 70) return "risk-badge-high";
    if (level === "medium" || score >= 30) return "risk-badge-medium";
    return "risk-badge-low";
}

export function protocolName(protocol) {
    const labels = { "1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP", "58": "ICMPv6" };
    return labels[String(protocol)] || `IP ${protocol}`;
}

export function anomalyIP(anomaly) {
    return anomaly.device_ip || anomaly.ip || anomaly.source_ip || anomaly.src_ip || anomaly.destination_ip || "-";
}

export function anomalyTime(anomaly) {
    return anomaly.detected_at || anomaly.created_at || anomaly.timestamp || anomaly.time;
}

export function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

export function linkForAlert(id) {
    return id ? `#/alerts/${encodeURIComponent(id)}` : "#/alerts";
}

export function emptyState(text) {
    return renderEmptyState(text);
}

export function errorState(text) {
    return renderErrorState(text);
}

export function overviewError(key) {
    return state.overviewErrors?.[key] || "";
}

export function subnetLabelFor(ip) {
    const parts = String(ip || "").split(".");
    if (parts.length < 3) return "Unknown";
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}
