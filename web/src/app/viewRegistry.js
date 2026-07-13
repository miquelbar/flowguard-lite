export const viewTitles = {
    overview: ["Overview", "Security posture, active attack signals, and coverage"],
    dashboard: ["Traffic", "Flow telemetry, risk signals, and local device activity"],
    devices: ["Devices", "Local inventory, labels, and learned baselines"],
    anomalies: ["Alerts", "Behavior changes that need review"],
    policies: ["Policies", "Define custom treatment rules for devices and alerts"],
    notifications: ["Notifications", "Route alerts by severity, type, and IP/subnet target"],
    audit: ["Audit", "Configuration changes and alert review history"],
    settings: ["Settings", "Runtime configuration for this FlowGuard node"]
};

export const routes = {
    "#/traffic": "dashboard",
    "#/dashboard": "dashboard",
    "#/overview": "overview",
    "#/devices": "devices",
    "#/alerts": "anomalies",
    "#/anomalies": "anomalies",
    "#/policies": "policies",
    "#/notifications": "notifications",
    "#/audit": "audit",
    "#/settings": "settings"
};

export function supportsGlobalTelemetryControls(viewName) {
    return viewName === "overview" || viewName === "dashboard";
}

