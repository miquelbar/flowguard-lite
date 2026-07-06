// Central fetch interceptor
async function apiFetch(url, options = {}) {
    const resp = await fetch(url, options);
    if (resp.status === 401) {
        if (window.showAuthOverlay) {
            window.showAuthOverlay("login", "Session expired. Sign in again.");
        }
        throw new Error("Unauthorized");
    }
    return resp;
}

export async function fetchHealth() {
    const resp = await apiFetch("/api/health");
    if (!resp.ok) throw new Error("Health check failed");
    return await resp.json();
}

export async function fetchExporters() {
    const resp = await apiFetch("/api/exporters");
    if (!resp.ok) throw new Error("Exporter query failed");
    return await resp.json();
}

export async function fetchTopTalkers(activeTab, range) {
    const params = new URLSearchParams({
        limit: "50",
        start: range.start.toISOString(),
        end: range.end.toISOString()
    });
    const resp = await apiFetch(`/api/top/${activeTab}?${params.toString()}`);
    if (!resp.ok) throw new Error("Top query failed");
    return await resp.json();
}

export async function fetchDevices() {
    const resp = await apiFetch("/api/devices");
    if (!resp.ok) throw new Error("Devices query failed");
    return await resp.json();
}

export async function fetchThreatRisk() {
    const resp = await apiFetch("/api/risk/devices");
    if (!resp.ok) throw new Error("Risk query failed");
    return await resp.json();
}

export async function fetchPolicies() {
    const resp = await apiFetch("/api/policies");
    if (!resp.ok) throw new Error("Policies query failed");
    return await resp.json();
}

export async function fetchAnomalies() {
    const resp = await apiFetch("/api/anomalies");
    if (!resp.ok) throw new Error("Anomalies query failed");
    return await resp.json();
}

export async function fetchNotificationRules() {
    const resp = await apiFetch("/api/notification-rules");
    if (!resp.ok) throw new Error("Notification rules query failed");
    return await resp.json();
}

export async function fetchNotificationLogs() {
    const resp = await apiFetch("/api/notification-logs?limit=50");
    if (!resp.ok) throw new Error("Notification logs query failed");
    return await resp.json();
}

export async function fetchTrafficTimeSeries(range) {
    const params = new URLSearchParams({
        start: range.start.toISOString(),
        end: range.end.toISOString(),
        bucket_seconds: String(range.bucket)
    });
    const resp = await apiFetch(`/api/traffic/timeseries?${params.toString()}`);
    if (!resp.ok) throw new Error("Traffic time-series query failed");
    return await resp.json();
}

export async function fetchSettings() {
    const resp = await apiFetch("/api/settings");
    if (!resp.ok) throw new Error("Settings fetch failed");
    return await resp.json();
}

export async function fetchAuditLogs() {
    const resp = await apiFetch("/api/audit-logs?limit=100");
    if (!resp.ok) throw new Error("Failed to query audit logs");
    return await resp.json();
}

export async function fetchFirewallTemplates(ip) {
    const resp = await apiFetch(`/api/firewall/rules?ip=${ip}`);
    if (!resp.ok) throw new Error("Failed to load rules templates");
    return await resp.json();
}

export async function submitLogin(password) {
    const resp = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password })
    });
    if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.error || "Authentication failed");
    }
    return true;
}

export async function submitLogout() {
    const resp = await fetch("/api/auth/logout", { method: "POST" });
    if (!resp.ok) throw new Error("Logout failed");
    return true;
}

export async function submitSetup(password) {
    const resp = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password })
    });
    if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.error || "Setup failed");
    }
    return true;
}

export async function updateAnomalyStatus(id, newStatus) {
    const resp = await apiFetch(`/api/anomalies/${id}/status`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus })
    });
    if (!resp.ok) throw new Error("Failed to update alert status");
    return true;
}

export async function saveSettings(category, data) {
    const resp = await apiFetch(`/api/settings?category=${category}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    });
    if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        throw new Error(errData.error || `Failed to save ${category} settings`);
    }
    return true;
}

export async function savePolicy(p) {
    const url = p.id ? `/api/policies/${p.id}` : "/api/policies";
    const method = p.id ? "PUT" : "POST";
    const resp = await apiFetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(p)
    });
    if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        throw new Error(errData.error || "Failed to save policy");
    }
    return true;
}

export async function deletePolicy(id) {
    const resp = await apiFetch(`/api/policies/${id}`, { method: "DELETE" });
    if (!resp.ok) throw new Error("Failed to delete policy");
    return true;
}

export async function saveNotificationRule(rule) {
    const url = rule.id ? `/api/notification-rules/${rule.id}` : "/api/notification-rules";
    const method = rule.id ? "PUT" : "POST";
    const resp = await apiFetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rule)
    });
    if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        throw new Error(errData.error || "Failed to save notification rule");
    }
    return true;
}

export async function deleteNotificationRule(id) {
    const resp = await apiFetch(`/api/notification-rules/${id}`, { method: "DELETE" });
    if (!resp.ok) throw new Error("Failed to delete notification rule");
    return true;
}

export async function testNotificationRule(id) {
    const resp = await apiFetch(`/api/notification-rules/${id}/test`, { method: "POST" });
    if (!resp.ok) throw new Error("Notification delivery test failed");
    return true;
}

export async function fetchDeviceProfile(ip) {
    const resp = await apiFetch(`/api/devices/${ip}`);
    if (!resp.ok) throw new Error("Failed to load device identity profile");
    return await resp.json();
}

export async function fetchDeviceFlows(ip, start, end) {
    const params = new URLSearchParams({
        start: start.toISOString(),
        end: end.toISOString()
    });
    const resp = await apiFetch(`/api/devices/${ip}/flows?${params.toString()}`);
    if (!resp.ok) throw new Error("Failed to load device flows timeline");
    return await resp.json();
}
