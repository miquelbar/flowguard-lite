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

async function responseError(resp, fallback) {
    const data = await resp.json().catch(() => ({}));
    return new Error(data.error || fallback);
}

async function getJSON(url, errorMessage) {
    const resp = await apiFetch(url);
    if (!resp.ok) throw await responseError(resp, errorMessage);
    return await resp.json();
}

async function sendJSON(url, body, options = {}) {
    const resp = await apiFetch(url, {
        method: options.method || "POST",
        headers: { "Content-Type": "application/json", ...(options.headers || {}) },
        body: body === undefined ? undefined : JSON.stringify(body)
    });
    if (!resp.ok) throw await responseError(resp, options.errorMessage || "Request failed");
    return resp;
}

async function sendEmpty(url, options = {}) {
    const resp = await apiFetch(url, { method: options.method || "POST" });
    if (!resp.ok) throw await responseError(resp, options.errorMessage || "Request failed");
    return resp;
}

function queryParams(values) {
    const params = new URLSearchParams();
    Object.entries(values).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== "") {
            params.set(key, String(value));
        }
    });
    return params;
}

function rangeQueryParams(range, values = {}) {
    return queryParams({
        ...values,
        start: range.start.toISOString(),
        end: range.end.toISOString()
    });
}

export async function fetchAuthStatus() {
    return await getJSON("/api/auth/status", "Auth status check failed");
}

export async function fetchHealth() {
    return await getJSON("/api/health", "Health check failed");
}

export async function fetchExporters() {
    return await getJSON("/api/exporters", "Exporter query failed");
}

export async function fetchTopTalkers(activeTab, range, limit = "50") {
    const params = rangeQueryParams(range, { limit });
    return await getJSON(`/api/top/${activeTab}?${params.toString()}`, "Top query failed");
}

export async function fetchDevices() {
    return await getJSON("/api/devices", "Devices query failed");
}

export async function fetchThreatRisk() {
    return await getJSON("/api/risk/devices", "Risk query failed");
}

export async function fetchPolicies() {
    return await getJSON("/api/policies", "Policies query failed");
}

export async function fetchAnomalies() {
    return await getJSON("/api/anomalies", "Anomalies query failed");
}

export async function fetchNotificationRules() {
    return await getJSON("/api/notification-rules", "Notification rules query failed");
}

export async function fetchNotificationLogs() {
    return await getJSON("/api/notification-logs?limit=50", "Notification logs query failed");
}

export async function fetchTrafficTimeSeries(range) {
    const params = rangeQueryParams(range, { bucket_seconds: range.bucket });
    return await getJSON(`/api/traffic/timeseries?${params.toString()}`, "Traffic time-series query failed");
}

export async function fetchTrafficRecords(range, filters = {}) {
    const params = rangeQueryParams(range, {
        limit: "200",
        q: filters.q,
        protocol: filters.protocol,
        dst_port: filters.dstPort
    });
    return await getJSON(`/api/traffic/records?${params.toString()}`, "Flow explorer query failed");
}

export async function fetchSecuritySummary() {
    return await getJSON("/api/security/summary", "Security summary query failed");
}

export async function fetchSecurityTimeline(range) {
    const params = rangeQueryParams(range, { bucket_seconds: range.bucket });
    return await getJSON(`/api/security/timeline?${params.toString()}`, "Security timeline query failed");
}

export async function fetchStatsProtocols(range) {
    const params = rangeQueryParams(range, { limit: "5" });
    return await getJSON(`/api/stats/protocols?${params.toString()}`, "Protocol stats query failed");
}

export async function fetchStatsTopDevices(range, limit = "5") {
    const params = rangeQueryParams(range, { limit });
    return await getJSON(`/api/stats/top-devices?${params.toString()}`, "Top devices stats query failed");
}

export async function fetchStatsHeatmap(range) {
    const params = rangeQueryParams(range, { limit: "10" });
    return await getJSON(`/api/stats/heatmap?${params.toString()}`, "Device heatmap query failed");
}

export async function fetchStatsCollectorHealth() {
    return await getJSON("/api/stats/collector-health?limit=120", "Collector health stats query failed");
}

export async function fetchSettings() {
    return await getJSON("/api/settings", "Settings fetch failed");
}

export async function fetchAuditLogs() {
    return await getJSON("/api/audit-logs?limit=100", "Failed to query audit logs");
}

export async function fetchFirewallTemplates(ip) {
    return await getJSON(`/api/firewall/rules?ip=${ip}`, "Failed to load rules templates");
}

export async function submitLogin(password) {
    await sendJSON("/api/auth/login", { password }, { errorMessage: "Authentication failed" });
    return true;
}

export async function submitLogout() {
    await sendEmpty("/api/auth/logout", { errorMessage: "Logout failed" });
    return true;
}

export async function submitSetup(password) {
    await sendJSON("/api/auth/setup", { password }, { errorMessage: "Setup failed" });
    return true;
}

export async function updateAnomalyStatus(id, newStatus) {
    await sendJSON(`/api/anomalies/${id}/status`, { status: newStatus }, {
        method: "PUT",
        errorMessage: "Failed to update alert status"
    });
    return true;
}

export async function saveSettings(category, data) {
    await sendJSON(`/api/settings?category=${category}`, data, {
        errorMessage: `Failed to save ${category} settings`
    });
    return true;
}

export async function savePolicy(p) {
    const url = p.id ? `/api/policies/${p.id}` : "/api/policies";
    const method = p.id ? "PUT" : "POST";
    await sendJSON(url, p, {
        method,
        errorMessage: "Failed to save policy"
    });
    return true;
}

export async function deletePolicy(id) {
    await sendEmpty(`/api/policies/${id}`, { method: "DELETE", errorMessage: "Failed to delete policy" });
    return true;
}

export async function saveNotificationRule(rule) {
    const url = rule.id ? `/api/notification-rules/${rule.id}` : "/api/notification-rules";
    const method = rule.id ? "PUT" : "POST";
    await sendJSON(url, rule, {
        method,
        errorMessage: "Failed to save notification rule"
    });
    return true;
}

export async function deleteNotificationRule(id) {
    await sendEmpty(`/api/notification-rules/${id}`, { method: "DELETE", errorMessage: "Failed to delete notification rule" });
    return true;
}

export async function testNotificationRule(id) {
    await sendEmpty(`/api/notification-rules/${id}/test`, { errorMessage: "Notification delivery test failed" });
    return true;
}

export async function testChannel(payload) {
    const resp = await sendJSON("/api/settings/test-channel", payload, {
        errorMessage: "Channel test connection failed"
    });
    return await resp.json();
}

export async function fetchDeviceProfile(ip) {
    return await getJSON(`/api/devices/${ip}`, "Failed to load device identity profile");
}

export async function fetchDeviceFlows(ip, start, end) {
    const params = queryParams({
        start: start.toISOString(),
        end: end.toISOString()
    });
    return await getJSON(`/api/devices/${ip}/flows?${params.toString()}`, "Failed to load device flows timeline");
}

export async function updateDeviceLabel(ip, label) {
    await sendJSON(`/api/devices/${ip}/label`, { label }, {
        method: "PUT",
        errorMessage: "Failed to update device label"
    });
    return true;
}

export async function fetchGlobalUniFiEvents(limit = 50) {
    return await getJSON(`/api/security/unifi-events?limit=${limit}`, "Failed to fetch UniFi events");
}

export async function fetchDeviceUniFiEvents(ip, limit = 50) {
    return await getJSON(`/api/devices/${ip}/unifi-events?limit=${limit}`, "Failed to fetch device UniFi events");
}
