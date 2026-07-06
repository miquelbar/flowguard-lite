// FlowGuard Lite Dashboard Logic Engine
document.addEventListener("DOMContentLoaded", () => {
    let activeView = "dashboard";
    const routeViews = {
        "#/traffic": "dashboard",
        "#/dashboard": "dashboard",
        "#/devices": "devices",
        "#/alerts": "anomalies",
        "#/anomalies": "anomalies",
        "#/policies": "policies",
        "#/notifications": "notifications",
        "#/audit": "audit",
        "#/settings": "settings"
    };

    const viewRoutes = {
        "dashboard": "#/traffic",
        "devices": "#/devices",
        "anomalies": "#/alerts",
        "policies": "#/policies",
        "notifications": "#/notifications",
        "audit": "#/audit",
        "settings": "#/settings"
    };
    let activeTab = "sources";
    let activeTriageFilter = "all";
    let autoRefreshTimer = null;
    
    // In-memory data states
    let talkersData = [];
    let exportersData = [];
    let devicesData = [];
    let anomaliesData = [];
    let riskDevicesData = [];
    let trafficSeriesData = [];
    let activeTrafficRange = "24h";
    let activeTrafficMetric = "bytes";
    let selectedDeviceIP = null;
    let selectedAnomalyId = null;
    let policiesData = [];
    let selectedPolicyId = null;
    let notificationRulesData = [];
    let selectedNotificationRuleId = null;
    let notificationLogsData = [];
    let auditLogPage = 0;
    let auditLogPageSize = 10;

    // Navigation elements
    const navDashboard = document.getElementById("nav-dashboard");
    const navDevices = document.getElementById("nav-devices");
    const navAnomalies = document.getElementById("nav-anomalies");
    const navPolicies = document.getElementById("nav-policies");
    const navNotifications = document.getElementById("nav-notifications");
    const navAudit = document.getElementById("nav-audit");
    const navSettings = document.getElementById("nav-settings");
    
    const viewDashboard = document.getElementById("view-dashboard");
    const viewDevices = document.getElementById("view-devices");
    const viewAnomalies = document.getElementById("view-anomalies");
    const viewPolicies = document.getElementById("view-policies");
    const viewNotifications = document.getElementById("view-notifications");
    const viewAudit = document.getElementById("view-audit");
    const viewSettings = document.getElementById("view-settings");
    const viewWizard = document.getElementById("view-wizard");

    // Elements
    const btnRefresh = document.getElementById("btn-refresh");
    const btnToggleSidebar = document.getElementById("btn-toggle-sidebar");
    const btnShowSidebar = document.getElementById("btn-show-sidebar");
    const btnLogout = document.getElementById("btn-logout");
    const statusIndicator = document.querySelector(".status-indicator");
    const statusLabel = document.querySelector(".status-label");
    const themeButtons = document.querySelectorAll(".theme-toggle-btn");
    const workspaceTitle = document.getElementById("workspace-title");
    const workspaceSubtitle = document.querySelector(".workspace-subtitle");
    const inputSearch = document.getElementById("input-search");
    const inputDeviceSearch = document.getElementById("input-device-search");
    const trafficChart = document.getElementById("traffic-chart");
    const trafficChartEmpty = document.getElementById("traffic-chart-empty");
    const trafficRangeButtons = document.querySelectorAll(".traffic-range-btn");
    const trafficMetricButtons = document.querySelectorAll(".traffic-metric-btn");
    const topTalkerSignal = document.getElementById("top-talker-signal");
    const portDistributionSignal = document.getElementById("port-distribution-signal");
    const subnetSummarySignal = document.getElementById("subnet-summary-signal");
    const authOverlay = document.getElementById("auth-overlay");
    const formAuth = document.getElementById("form-auth");
    const authPassword = document.getElementById("auth-password");
    const authTitle = document.getElementById("auth-title");
    const authSubtitle = document.getElementById("auth-subtitle");
    const authMessage = document.getElementById("auth-message");
    const btnAuthSubmit = document.getElementById("btn-auth-submit");
    let authMode = "login";
    
    // Unsaved settings tracking
    const unsavedChanges = {
        access: false,
        network: false,
        collectors: false,
        storage: false,
        thresholds: false,
        notifications: false,
        system: false
    };
    
    // Stats elements
    const valPackets = document.getElementById("val-packets");
    const valDrops = document.getElementById("val-drops");
    const valErrors = document.getElementById("val-errors");
    const valQueue = document.getElementById("val-queue");

    // Table elements
    const tblExporters = document.getElementById("tbl-exporters").querySelector("tbody");
    const tblTopTalkers = document.getElementById("tbl-top-talkers").querySelector("tbody");
    const tblDevices = document.getElementById("tbl-devices").querySelector("tbody");
    const tblAnomalies = document.getElementById("tbl-anomalies").querySelector("tbody");
    const tblThreatRisk = document.getElementById("tbl-threat-risk").querySelector("tbody");
    
    const tabButtons = document.querySelectorAll(".filter-controls .tab-btn");
    const triageFilterButtons = document.querySelectorAll(".triage-filter-btn");

    // Device Detail elements
    const detailsEmpty = document.getElementById("device-details-empty");
    const detailsContent = document.getElementById("device-details-content");
    const detailIp = document.getElementById("detail-ip");
    const detailHost = document.getElementById("detail-host");
    const formUpdateLabel = document.getElementById("form-update-label");
    const inputDetailLabel = document.getElementById("input-detail-label");
    const baselineStatsContent = document.getElementById("baseline-stats-content");
    const detailRiskBadgeContainer = document.getElementById("detail-risk-badge-container");
    const detailRiskExplanationSection = document.getElementById("detail-risk-explanation-section");
    const detailRiskExplanationContent = document.getElementById("detail-risk-explanation-content");
    const detailSubnet = document.getElementById("detail-subnet");
    const detailFirstSeen = document.getElementById("detail-first-seen");
    const detailLastSeen = document.getElementById("detail-last-seen");
    const deviceChartContainer = document.getElementById("device-chart-container");
    const tblDevicePeers = document.getElementById("tbl-device-peers").querySelector("tbody");
    const tblDevicePorts = document.getElementById("tbl-device-ports").querySelector("tbody");
    const deviceAlertsList = document.getElementById("device-alerts-list");
    const btnDeviceFwRules = document.getElementById("btn-device-fw-rules");

    // Anomaly Detail elements
    const anomalyDetailsEmpty = document.getElementById("anomaly-details-empty");
    const anomalyDetailsContent = document.getElementById("anomaly-details-content");
    const anomalyDetailIp = document.getElementById("anomaly-detail-ip");
    const anomalyDetailType = document.getElementById("anomaly-detail-type");
    const anomalyDetailDescription = document.getElementById("anomaly-detail-description");
    const anomalyDetailTime = document.getElementById("anomaly-detail-time");
    const anomalyDetailStatus = document.getElementById("anomaly-detail-status");
    const anomalyDetailActions = document.getElementById("anomaly-detail-actions");
    const anomalyDetailBadgeContainer = document.getElementById("anomaly-detail-badge-container");

    // Toast elements
    const toastContainer = document.getElementById("toast-container");

    // Policies view elements
    const tblPolicies = document.getElementById("tbl-policies") ? document.getElementById("tbl-policies").querySelector("tbody") : null;
    const btnAddPolicy = document.getElementById("btn-add-policy");
    const panelPolicyDetails = document.getElementById("panel-policy-details");
    const policyDetailsEmpty = document.getElementById("policy-details-empty");
    const policyDetailsContent = document.getElementById("policy-details-content");
    const policyDetailsTitle = document.getElementById("policy-details-title");
    const btnClosePolicyDetails = document.getElementById("btn-close-policy-details");

    const formPolicyEditor = document.getElementById("form-policy-editor");
    const inputPolicyId = document.getElementById("policy-id");
    const inputPolicyName = document.getElementById("policy-name");
    const selectPolicyScope = document.getElementById("policy-scope");
    const inputPolicyTarget = document.getElementById("policy-target");
    const labelPolicyTarget = document.getElementById("lbl-policy-target");
    const selectPolicySeverityThreshold = document.getElementById("policy-severity-threshold");
    const selectPolicyCooldown = document.getElementById("policy-cooldown");
    const inputPolicyQuietHoursStart = document.getElementById("policy-quiet-hours-start");
    const inputPolicyQuietHoursEnd = document.getElementById("policy-quiet-hours-end");
    const inputPolicySuppressed = document.getElementById("policy-suppressed");
    const policyPrecedencePreview = document.getElementById("policy-precedence-preview");
    const btnCancelPolicy = document.getElementById("btn-cancel-policy");
    const devicePoliciesList = document.getElementById("device-policies-list");

    const tblNotificationRules = document.getElementById("tbl-notification-rules");
    const tblNotificationLogs = document.getElementById("tbl-notification-logs");
    const selectNotificationLogsLimit = document.getElementById("notification-logs-limit");
    const btnAddNotificationRule = document.getElementById("btn-add-notification-rule");
    const panelNotificationDetails = document.getElementById("panel-notification-details");
    const notificationDetailsTitle = document.getElementById("notification-details-title");
    const btnCloseNotificationDetails = document.getElementById("btn-close-notification-details");
    const notificationDetailsEmpty = document.getElementById("notification-details-empty");
    const notificationDetailsContent = document.getElementById("notification-details-content");

    // Form elements
    const formNotificationEditor = document.getElementById("form-notification-editor");
    const inputNotificationRuleId = document.getElementById("notification-rule-id");
    const inputNotificationRuleName = document.getElementById("notification-rule-name");
    const inputNotificationRuleEnabled = document.getElementById("notification-rule-enabled");
    const selectNotificationRuleSeverity = document.getElementById("notification-rule-severity");
    const inputNotificationRuleAlertTypes = document.getElementById("notification-rule-alert-types");
    const selectNotificationRuleScope = document.getElementById("notification-rule-scope");
    const groupNotificationTarget = document.getElementById("group-notification-target");
    const labelNotificationTarget = document.getElementById("label-notification-target");
    const inputNotificationRuleTarget = document.getElementById("notification-rule-target");
    const inputNotificationRuleCooldown = document.getElementById("notification-rule-cooldown");
    const btnDeleteNotificationRule = document.getElementById("btn-delete-notification-rule");
    const btnTestNotificationRule = document.getElementById("btn-test-notification-rule");
    const textNotificationRulePreview = document.getElementById("notification-rule-preview");

    // Helper: format bytes into human-readable representation
    function formatBytes(bytes) {
        if (bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB", "TB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    // Helper: format numbers with comma grouping
    function formatNumber(num) {
        return num.toLocaleString();
    }

    // Helper: format date/time string
    function formatTime(isoStr) {
        if (!isoStr) return "-";
        const date = new Date(isoStr);
        return date.toLocaleTimeString() + " " + date.toLocaleDateString();
    }

    function formatShortTime(date) {
        return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }

    // Helper: show toast notification
    function showToast(message, type = "success") {
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.textContent = message;
        toastContainer.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = "0";
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    function showAuthOverlay(mode, message = "") {
        authMode = mode;
        if (!authOverlay) return;
        authTitle.textContent = mode === "setup" ? "Set Admin Password" : "FlowGuard Lite";
        authSubtitle.textContent = mode === "setup"
            ? "Create the local admin password for this FlowGuard node"
            : "Sign in to this FlowGuard node";
        btnAuthSubmit.textContent = mode === "setup" ? "Create Password" : "Sign In";
        authPassword.value = "";
        authPassword.autocomplete = mode === "setup" ? "new-password" : "current-password";
        authMessage.textContent = message;
        authOverlay.classList.remove("hidden");
        authPassword.focus();
    }

    function hideAuthOverlay() {
        if (authOverlay) authOverlay.classList.add("hidden");
    }

    async function fetchAuthStatus() {
        const resp = await fetch("/api/auth/status");
        if (!resp.ok) throw new Error("Authentication status check failed");
        return resp.json();
    }

    async function submitAuth(password) {
        const endpoint = authMode === "setup" ? "/api/auth/setup" : "/api/auth/login";
        const resp = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password })
        });
        if (!resp.ok) {
            let msg = "Authentication failed";
            try {
                const err = await resp.json();
                msg = err.error || msg;
            } catch (_) {
                // Keep generic message if server did not return JSON.
            }
            throw new Error(msg);
        }
        return resp.json();
    }

    formAuth.addEventListener("submit", async (e) => {
        e.preventDefault();
        const password = authPassword.value;
        try {
            authMessage.textContent = "";
            await submitAuth(password);
            hideAuthOverlay();
            await initAuthenticatedApp();
        } catch (err) {
            authMessage.textContent = err.message;
        }
    });

    if (btnLogout) {
        btnLogout.addEventListener("click", async () => {
            try {
                await fetch("/api/auth/logout", { method: "POST" });
            } finally {
                if (autoRefreshTimer) {
                    clearInterval(autoRefreshTimer);
                    autoRefreshTimer = null;
                }
                showAuthOverlay("login", "Signed out.");
            }
        });
    }

    // Fetch Stats & Health counters
    async function fetchHealth() {
        try {
            const resp = await fetch("/api/health");
            if (!resp.ok) throw new Error("Health check failed");
            const data = await resp.json();
            
            if (data.collector) {
                valPackets.textContent = formatNumber(data.collector.packets_received);
                valDrops.textContent = formatNumber(data.collector.packets_dropped);
                valErrors.textContent = formatNumber(data.collector.decode_errors);
                valQueue.textContent = formatNumber(data.collector.queue_depth);
            }

            if (statusIndicator) {
                statusIndicator.classList.remove("offline");
                statusIndicator.classList.add("online");
            }
            if (statusLabel) {
                statusLabel.textContent = "Collector running";
            }
        } catch (err) {
            console.error("Error fetching health: ", err);
            if (statusIndicator) {
                statusIndicator.classList.remove("online");
                statusIndicator.classList.add("offline");
            }
            if (statusLabel) {
                statusLabel.textContent = "Disconnected";
            }
        }
    }

    // Fetch Exporter registry
    async function fetchExporters() {
        try {
            const resp = await fetch("/api/exporters");
            if (!resp.ok) throw new Error("Exporters query failed");
            exportersData = await resp.json();
            renderExporters();
        } catch (err) {
            console.error("Error fetching exporters: ", err);
        }
    }

    // Fetch Top Talkers depending on active tab
    async function fetchTopTalkers() {
        try {
            const range = trafficRangeConfig();
            const params = new URLSearchParams({
                limit: "50",
                start: range.start.toISOString(),
                end: range.end.toISOString()
            });
            const resp = await fetch(`/api/top/${activeTab}?${params.toString()}`);
            if (!resp.ok) throw new Error("Top query failed");
            talkersData = await resp.json();
            renderTopTalkers();
        } catch (err) {
            console.error(`Error fetching top ${activeTab}: `, err);
        }
    }

    // Fetch Device Inventory list
    async function fetchDevices() {
        try {
            const resp = await fetch("/api/devices");
            if (!resp.ok) throw new Error("Devices query failed");
            devicesData = await resp.json();
            renderDevices();
        } catch (err) {
            console.error("Error fetching devices: ", err);
        }
    }

    // Fetch Threat Risk Scoring ranks
    async function fetchThreatRisk() {
        try {
            const resp = await fetch("/api/risk/devices");
            if (!resp.ok) throw new Error("Risk query failed");
            riskDevicesData = await resp.json();
            renderThreatRisk();
        } catch (err) {
            console.error("Error fetching threat risk scores: ", err);
        }
    }

    // Fetch Policies configuration
    async function fetchPolicies() {
        try {
            const resp = await fetch("/api/policies");
            if (!resp.ok) throw new Error("Policies query failed");
            policiesData = await resp.json();
            renderPolicies();
        } catch (err) {
            console.error("Error fetching policies: ", err);
        }
    }

    // Fetch Anomalies list
    async function fetchAnomalies() {
        try {
            const resp = await fetch("/api/anomalies?limit=100");
            if (!resp.ok) throw new Error("Anomalies query failed");
            anomaliesData = await resp.json();
            renderAnomalies();

            if (selectedAnomalyId) {
                const anom = anomaliesData.find(a => a.id.toString() === selectedAnomalyId);
                if (anom) {
                    selectAnomaly(selectedAnomalyId);
                } else {
                    selectedAnomalyId = null;
                    anomalyDetailsEmpty.classList.remove("hidden");
                    anomalyDetailsContent.classList.add("hidden");
                }
            }
        } catch (err) {
            console.error("Error fetching anomalies: ", err);
        }
    }

    function trafficRangeConfig() {
        const end = new Date();
        const configs = {
            "1h": { start: new Date(end.getTime() - 60 * 60 * 1000), bucket: 60 },
            "6h": { start: new Date(end.getTime() - 6 * 60 * 60 * 1000), bucket: 300 },
            "24h": { start: new Date(end.getTime() - 24 * 60 * 60 * 1000), bucket: 900 },
            "7d": { start: new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000), bucket: 3600 }
        };
        return { ...configs[activeTrafficRange], end };
    }

    async function fetchTrafficTimeSeries() {
        try {
            const range = trafficRangeConfig();
            const params = new URLSearchParams({
                start: range.start.toISOString(),
                end: range.end.toISOString(),
                bucket_seconds: String(range.bucket)
            });
            const resp = await fetch(`/api/traffic/timeseries?${params.toString()}`);
            if (!resp.ok) throw new Error("Traffic time-series query failed");
            trafficSeriesData = await resp.json();
            renderTrafficChart();
        } catch (err) {
            console.error("Error fetching traffic time series: ", err);
            trafficSeriesData = [];
            renderTrafficChart();
        }
    }

    function renderTrafficChart() {
        if (!trafficChart) return;
        const width = 900;
        const height = 260;
        const pad = { top: 18, right: 22, bottom: 32, left: 74 };
        const plotW = width - pad.left - pad.right;
        const plotH = height - pad.top - pad.bottom;
        trafficChart.innerHTML = "";

        const points = (trafficSeriesData || []).map(item => ({
            ts: new Date(item.timestamp).getTime(),
            value: Number(item[activeTrafficMetric] || 0),
            raw: item
        })).filter(item => Number.isFinite(item.ts));

        if (trafficChartEmpty) trafficChartEmpty.classList.toggle("hidden", points.length > 0);
        if (points.length === 0) {
            trafficChart.innerHTML = `<text x="${width / 2}" y="${height / 2}" text-anchor="middle" class="chart-muted">No data</text>`;
            renderNetworkSignals();
            return;
        }

        const minTs = Math.min(...points.map(p => p.ts));
        const maxTs = Math.max(...points.map(p => p.ts));
        const maxValue = Math.max(...points.map(p => p.value), 1);
        const tsSpan = Math.max(maxTs - minTs, 1);
        const xFor = ts => pad.left + ((ts - minTs) / tsSpan) * plotW;
        const yFor = value => pad.top + plotH - (value / maxValue) * plotH;

        const gridLines = [0, 0.25, 0.5, 0.75, 1].map(frac => {
            const y = pad.top + plotH - (frac * plotH);
            const label = activeTrafficMetric === "bytes" ? formatBytes(maxValue * frac) : formatNumber(Math.round(maxValue * frac));
            return `<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" class="chart-grid"></line>
                    <text x="${pad.left - 10}" y="${y + 4}" text-anchor="end" class="chart-axis">${label}</text>`;
        }).join("");

        const pathData = points.map((p, idx) => `${idx === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yFor(p.value).toFixed(2)}`).join(" ");
        const areaData = `${pathData} L ${xFor(points[points.length - 1].ts).toFixed(2)} ${pad.top + plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top + plotH} Z`;
        const firstLabel = formatShortTime(new Date(minTs));
        const lastLabel = formatShortTime(new Date(maxTs));
        const singleSampleGuide = points.length === 1
            ? `<line x1="${xFor(points[0].ts).toFixed(2)}" y1="${pad.top}" x2="${xFor(points[0].ts).toFixed(2)}" y2="${pad.top + plotH}" class="chart-sample-guide"></line>`
            : "";

        const anomalyMarkers = (anomaliesData || []).map(anom => {
            const ts = new Date(anom.created_at).getTime();
            if (!Number.isFinite(ts) || ts < minTs || ts > maxTs) return "";
            const x = xFor(ts);
            const colorClass = anom.severity === "high" ? "chart-marker-high" : "chart-marker-medium";
            return `<line x1="${x}" y1="${pad.top}" x2="${x}" y2="${pad.top + plotH}" class="chart-marker ${colorClass}">
                    <title>${anom.type}: ${anom.ip}</title></line>`;
        }).join("");

        trafficChart.innerHTML = `
            <defs>
                <linearGradient id="trafficAreaFill" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stop-color="currentColor" stop-opacity="0.20"></stop>
                    <stop offset="100%" stop-color="currentColor" stop-opacity="0.02"></stop>
                </linearGradient>
            </defs>
            ${gridLines}
            <path d="${areaData}" class="chart-area"></path>
            <path d="${pathData}" class="chart-line"></path>
            ${singleSampleGuide}
            ${points.map(p => `<circle cx="${xFor(p.ts).toFixed(2)}" cy="${yFor(p.value).toFixed(2)}" r="${points.length === 1 ? 4.5 : 2.3}" class="chart-point"><title>${formatTime(p.raw.timestamp)} - ${activeTrafficMetric}: ${activeTrafficMetric === "bytes" ? formatBytes(p.value) : formatNumber(p.value)}</title></circle>`).join("")}
            ${anomalyMarkers}
            <text x="${pad.left}" y="${height - 8}" class="chart-axis">${firstLabel}</text>
            <text x="${width - pad.right}" y="${height - 8}" text-anchor="end" class="chart-axis">${lastLabel}</text>
        `;
        renderNetworkSignals();
    }

    function renderNetworkSignals() {
        renderTopTalkerSignal();
        renderPortDistributionSignal();
        renderSubnetSummarySignal();
    }

    function renderTopTalkerSignal() {
        if (!topTalkerSignal) return;
        const range = trafficRangeConfig();
        const params = new URLSearchParams({
            limit: "3",
            start: range.start.toISOString(),
            end: range.end.toISOString()
        });
        fetch(`/api/top/sources?${params.toString()}`)
            .then(resp => resp.ok ? resp.json() : [])
            .then(sources => {
                const sortedSources = [...sources].sort((a, b) => b.bytes - a.bytes);
                if (sortedSources.length === 0) {
                    topTalkerSignal.textContent = "No top talker data in the active window.";
                    return;
                }
                const totalBytes = sortedSources.reduce((sum, item) => sum + item.bytes, 0) || 1;
                topTalkerSignal.innerHTML = sortedSources.map(item => {
                    const pct = (item.bytes / totalBytes) * 100;
                    return `<div class="signal-row">
                        <span class="signal-key">${item.key}</span>
                        <span class="signal-value">${pct.toFixed(1)}%</span>
                        <div class="signal-bar"><span style="width:${Math.max(pct, 2)}%"></span></div>
                    </div>`;
                }).join("");
            })
            .catch(() => {
                topTalkerSignal.textContent = "Top talker share unavailable.";
            });
    }

    function protocolName(protocol) {
        const labels = {
            "1": "ICMP",
            "6": "TCP",
            "17": "UDP",
            "47": "GRE",
            "50": "ESP",
            "58": "ICMPv6"
        };
        return labels[String(protocol)] || `IP ${protocol}`;
    }

    function renderPortDistributionSignal() {
        if (!portDistributionSignal) return;
        const range = trafficRangeConfig();
        const params = new URLSearchParams({
            limit: "6",
            start: range.start.toISOString(),
            end: range.end.toISOString()
        });
        Promise.all([
            fetch(`/api/top/protocols?${params.toString()}`).then(resp => resp.ok ? resp.json() : []),
            fetch(`/api/top/ports?${params.toString()}`).then(resp => resp.ok ? resp.json() : [])
        ])
            .then(([protocols, ports]) => {
                if ((!protocols || protocols.length === 0) && (!ports || ports.length === 0)) {
                    portDistributionSignal.textContent = "No protocol or destination port data in the active window.";
                    return;
                }

                const protocolTotal = protocols.reduce((sum, item) => sum + item.bytes, 0) || 1;
                const portTotal = ports.reduce((sum, item) => sum + item.bytes, 0) || 1;
                const protocolRows = protocols.slice(0, 2).map(item => {
                    const pct = (item.bytes / protocolTotal) * 100;
                    return `<div class="signal-row">
                        <span class="signal-key">${protocolName(item.key)}</span>
                        <span class="signal-value">${pct.toFixed(0)}%</span>
                        <div class="signal-bar signal-bar-protocol"><span style="width:${Math.max(pct, 2)}%"></span></div>
                    </div>`;
                }).join("");
                const portRows = ports.slice(0, 3).map(item => {
                    const pct = (item.bytes / portTotal) * 100;
                    return `<div class="signal-row">
                        <span class="signal-key">:${item.key}</span>
                        <span class="signal-value">${formatBytes(item.bytes)}</span>
                        <div class="signal-bar"><span style="width:${Math.max(pct, 2)}%"></span></div>
                    </div>`;
                }).join("");

                portDistributionSignal.innerHTML = `
                    ${protocolRows ? `<div class="signal-section-label">Protocols</div>${protocolRows}` : ""}
                    ${portRows ? `<div class="signal-section-label">Destination ports</div>${portRows}` : ""}
                `;
            })
            .catch(() => {
                portDistributionSignal.textContent = "Protocol and port distribution unavailable.";
            });
    }

    function subnetLabelFor(ip) {
        const parts = ip.split(".");
        if (parts.length < 3) return "Unknown";
        return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }

    function renderSubnetSummarySignal() {
        if (!subnetSummarySignal) return;
        const summary = new Map();
        devicesData.forEach(dev => {
            const subnet = subnetLabelFor(dev.ip);
            if (!summary.has(subnet)) summary.set(subnet, { count: 0, risk: 0 });
            summary.get(subnet).count += 1;
        });
        riskDevicesData.forEach(dev => {
            const subnet = subnetLabelFor(dev.ip);
            if (!summary.has(subnet)) summary.set(subnet, { count: 0, risk: 0 });
            summary.get(subnet).risk += 1;
        });
        if (summary.size === 0) {
            subnetSummarySignal.textContent = "No discovered local subnets yet.";
            return;
        }
        subnetSummarySignal.innerHTML = [...summary.entries()].sort().slice(0, 4).map(([subnet, val]) => `
            <div class="subnet-row">
                <span class="signal-key">${subnet}</span>
                <span class="signal-value">${val.count} devices · ${val.risk} risky</span>
            </div>
        `).join("");
    }

    // Render Exporters to table
    function renderExporters() {
        if (!exportersData || exportersData.length === 0) {
            tblExporters.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No active exporters observed.</td></tr>`;
            return;
        }

        tblExporters.innerHTML = exportersData.map(exp => `
            <tr>
                <td>${exp.ip}</td>
                <td>${formatTime(exp.last_seen)}</td>
                <td class="text-right">${formatNumber(exp.packet_count)}</td>
            </tr>
        `).join('');
    }

    // Render Threat Risk Ranking to table
    function renderThreatRisk() {
        if (!riskDevicesData || riskDevicesData.length === 0) {
            tblThreatRisk.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No elevated-risk devices.</td></tr>`;
            return;
        }

        tblThreatRisk.innerHTML = riskDevicesData.map(dev => {
            const badgeClass = dev.risk_level === "high" ? "risk-badge-high" : (dev.risk_level === "medium" ? "risk-badge-medium" : "risk-badge-low");
            
            // Build dynamic summary text
            let summaryText = "";
            if (dev.breakdown) {
                const parts = [];
                const highCount = (dev.breakdown.alert_breakdown || []).filter(c => c.severity === "high").length;
                const medCount = (dev.breakdown.alert_breakdown || []).filter(c => c.severity === "medium").length;
                const lowCount = (dev.breakdown.alert_breakdown || []).filter(c => c.severity === "low").length;
                
                if (highCount > 0) parts.push(`${highCount} high`);
                if (medCount > 0) parts.push(`${medCount} med`);
                if (lowCount > 0) parts.push(`${lowCount} low`);
                
                let contributors = parts.join(", ");
                if (contributors) {
                    summaryText = `${contributors}`;
                }
                if (dev.breakdown.correlation_boost > 0) {
                    if (summaryText) {
                        summaryText += ` + boost (+${dev.breakdown.correlation_boost} pts)`;
                    } else {
                        summaryText = `Correlation boost (+${dev.breakdown.correlation_boost} pts)`;
                    }
                }
            }

            return `
                <tr style="cursor: pointer;" class="threat-device-row" data-ip="${dev.ip}">
                    <td>
                        <div class="risk-device-cell" style="display: flex; flex-direction: column; gap: 0.15rem;">
                            <div style="display: flex; gap: 0.5rem; align-items: center;">
                                <span class="risk-device-ip"><a href="#/devices/${dev.ip}" class="ip-link">${dev.ip}</a></span>
                                ${dev.label ? `<span class="badge badge-label risk-device-label">${dev.label}</span>` : ''}
                            </div>
                            ${summaryText ? `<span class="text-muted" style="font-size: 0.72rem; line-height: 1.2;">Contributors: ${summaryText}</span>` : ''}
                        </div>
                    </td>
                    <td><span class="risk-badge ${badgeClass} risk-score-badge">${dev.risk_score}</span></td>
                    <td class="text-right text-muted" style="text-transform: capitalize;">${dev.risk_level}</td>
                </tr>
            `;
        }).join('');

        // Clicking a threat device row navigates to devices page and selects it
        tblThreatRisk.querySelectorAll(".threat-device-row").forEach(row => {
            row.addEventListener("click", (e) => {
                if (e.target.tagName === "A") return;
                const ip = row.getAttribute("data-ip");
                window.location.hash = `#/devices/${ip}`;
            });
        });
    }

    // Render Top Talkers to table with progress bars
    function renderTopTalkers() {
        const query = inputSearch.value.trim().toLowerCase();
        const filtered = talkersData.filter(item => item.key.toLowerCase().includes(query));

        if (filtered.length === 0) {
            tblTopTalkers.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No records match the active filters.</td></tr>`;
            return;
        }

        const maxBytes = Math.max(...filtered.map(i => i.bytes), 1);

        tblTopTalkers.innerHTML = filtered.map(item => {
            const percentage = (item.bytes / maxBytes) * 100;
            const isIP = activeTab === "sources" || activeTab === "destinations";
            const keyHtml = isIP ? `<a href="#/devices/${item.key}" class="ip-link">${item.key}</a>` : item.key;
            return `
                <tr>
                    <td class="font-semibold">${keyHtml}</td>
                    <td class="text-right">${formatNumber(item.flows)}</td>
                    <td class="text-right">${formatNumber(item.packets)}</td>
                    <td class="text-right">${formatBytes(item.bytes)}</td>
                    <td class="width-progress">
                        <div class="progress-track" title="${percentage.toFixed(1)}%">
                            <div class="progress-bar" style="width: ${percentage}%"></div>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    }

    // Render policies table
    function renderPolicies() {
        if (!tblPolicies) return;
        if (policiesData.length === 0) {
            tblPolicies.innerHTML = `<tr><td colspan="6" class="text-center text-muted pad-large">No policies configured yet.</td></tr>`;
            return;
        }

        tblPolicies.innerHTML = policiesData.map(p => {
            const isSelected = selectedPolicyId === p.id;
            const suppressedText = p.suppressed 
                ? '<span class="badge badge-label text-warning" style="background-color: rgba(245,158,11,0.1); border-color: rgba(245,158,11,0.2);">Silenced</span>' 
                : '<span class="badge badge-label text-success" style="background-color: rgba(16,185,129,0.1); border-color: rgba(16,185,129,0.2);">Active</span>';
            const scopeBadge = `<span class="badge badge-label" style="background-color: rgba(56,189,248,0.1); border-color: rgba(56,189,248,0.2); color: #38bdf8; text-transform: uppercase;">${p.scope}</span>`;
            
            let priorityBadge = "";
            if (p.scope === "ip") {
                priorityBadge = `<span class="badge badge-label" style="background-color: rgba(16,185,129,0.1); border-color: rgba(16,185,129,0.2); color: #10b981; font-weight: 600;">4 (Highest)</span>`;
            } else if (p.scope === "subnet") {
                priorityBadge = `<span class="badge badge-label" style="background-color: rgba(56,189,248,0.1); border-color: rgba(56,189,248,0.2); color: #38bdf8;">3</span>`;
            } else if (p.scope === "alert_type") {
                priorityBadge = `<span class="badge badge-label" style="background-color: rgba(251,146,60,0.1); border-color: rgba(251,146,60,0.2); color: #fb923c;">2</span>`;
            } else {
                priorityBadge = `<span class="badge badge-label" style="background-color: rgba(148,163,184,0.1); border-color: rgba(148,163,184,0.2); color: #94a3b8;">1 (Lowest)</span>`;
            }

            return `
                <tr data-id="${p.id}" class="${isSelected ? 'selected' : ''}" style="cursor: pointer;">
                    <td class="font-semibold">${escapeHtml(p.name)}</td>
                    <td>${scopeBadge}</td>
                    <td>${priorityBadge}</td>
                    <td class="text-muted font-mono" style="font-size: 0.813rem;">${escapeHtml(p.target || "(all)")}</td>
                    <td>${suppressedText}</td>
                    <td class="text-center">
                        <button class="btn-secondary btn-select-policy" data-id="${p.id}">Select</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Listeners for selection
        tblPolicies.querySelectorAll("tr").forEach(row => {
            row.addEventListener("click", (e) => {
                if (e.target.tagName === "BUTTON") return;
                const id = parseInt(row.getAttribute("data-id"));
                selectPolicyId(id);
            });
        });

        tblPolicies.querySelectorAll(".btn-select-policy").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const id = parseInt(e.target.getAttribute("data-id"));
                selectPolicyId(id);
            });
        });
    }

    function selectPolicyId(id) {
        selectedPolicyId = id;
        const p = policiesData.find(x => x.id === id);
        if (p) {
            selectPolicy(p);
        } else {
            resetPolicyDetails();
        }
        renderPolicies();
    }

    function selectPolicy(p) {
        selectedPolicyId = p.id;
        inputPolicyId.value = p.id;
        inputPolicyName.value = p.name;
        selectPolicyScope.value = p.scope;
        inputPolicyTarget.value = p.target || "";
        selectPolicySeverityThreshold.value = p.severity_threshold || "";
        selectPolicyCooldown.value = p.cooldown_seconds || "0";
        inputPolicyQuietHoursStart.value = p.quiet_hours_start || "";
        inputPolicyQuietHoursEnd.value = p.quiet_hours_end || "";
        inputPolicySuppressed.checked = p.suppressed;

        // Set channel checkboxes
        const channels = p.notification_channels || [];
        document.querySelectorAll(".policy-channel-checkbox").forEach(cb => {
            cb.checked = channels.includes(cb.value);
        });

        // Update labels
        updateTargetFieldLabel();

        const btnDelete = document.getElementById("btn-delete-policy");
        if (btnDelete) btnDelete.classList.remove("hidden");

        policyDetailsTitle.textContent = `Edit Policy: ${p.name}`;
        policyDetailsEmpty.classList.add("hidden");
        policyDetailsContent.classList.remove("hidden");

        // Precedence & conflict display
        updatePrecedencePreview();
    }

    function startAddPolicy() {
        selectedPolicyId = "new";
        inputPolicyId.value = "";
        inputPolicyName.value = "";
        selectPolicyScope.value = "global";
        inputPolicyTarget.value = "";
        selectPolicySeverityThreshold.value = "";
        selectPolicyCooldown.value = "0";
        inputPolicyQuietHoursStart.value = "";
        inputPolicyQuietHoursEnd.value = "";
        inputPolicySuppressed.checked = false;

        document.querySelectorAll(".policy-channel-checkbox").forEach(cb => {
            cb.checked = false;
        });

        updateTargetFieldLabel();

        const btnDelete = document.getElementById("btn-delete-policy");
        if (btnDelete) btnDelete.classList.add("hidden");

        policyDetailsTitle.textContent = "New Policy";
        policyDetailsEmpty.classList.add("hidden");
        policyDetailsContent.classList.remove("hidden");

        updatePrecedencePreview();
        renderPolicies();
    }

    function resetPolicyDetails() {
        selectedPolicyId = null;
        if (policyDetailsEmpty) policyDetailsEmpty.classList.remove("hidden");
        if (policyDetailsContent) policyDetailsContent.classList.add("hidden");
    }

    function updateTargetFieldLabel() {
        const scope = selectPolicyScope.value;
        if (scope === "global") {
            inputPolicyTarget.disabled = true;
            inputPolicyTarget.value = "";
            inputPolicyTarget.required = false;
            labelPolicyTarget.innerHTML = 'Target <span class="text-muted">(N/A for Global)</span>';
            inputPolicyTarget.placeholder = "All traffic and alerts";
        } else if (scope === "ip") {
            inputPolicyTarget.disabled = false;
            inputPolicyTarget.required = true;
            labelPolicyTarget.innerHTML = 'Device IP Address <span class="text-danger">*</span>';
            inputPolicyTarget.placeholder = "e.g. 192.168.1.50";
        } else if (scope === "subnet") {
            inputPolicyTarget.disabled = false;
            inputPolicyTarget.required = true;
            labelPolicyTarget.innerHTML = 'Subnet / VLAN CIDR <span class="text-danger">*</span>';
            inputPolicyTarget.placeholder = "e.g. 192.168.1.0/24";
        } else if (scope === "alert_type") {
            inputPolicyTarget.disabled = false;
            inputPolicyTarget.required = true;
            labelPolicyTarget.innerHTML = 'Alert Type / Rule Name <span class="text-danger">*</span>';
            inputPolicyTarget.placeholder = "e.g. port_scan, outbound_volume";
        }
    }

    // Dynamic precedence overlap preview
    function updatePrecedencePreview() {
        if (!policyPrecedencePreview) return;
        const scope = selectPolicyScope.value;
        const target = inputPolicyTarget.value.trim();
        const suppressed = inputPolicySuppressed.checked;
        const severity = selectPolicySeverityThreshold.value;
        const startQH = inputPolicyQuietHoursStart.value.trim();
        const endQH = inputPolicyQuietHoursEnd.value.trim();

        let previewHtml = "";

        // 1. Describe current policy behavior
        let behavior = "<strong>Scope Preview:</strong> ";
        if (scope === "global") {
            behavior += "Applies globally to all traffic and anomalies.";
        } else if (scope === "ip") {
            behavior += `Applies exclusively to device <code>${escapeHtml(target || "IP address")}</code>.`;
        } else if (scope === "subnet") {
            behavior += `Applies to all devices belonging to subnet CIDR range <code>${escapeHtml(target || "CIDR")}</code>.`;
        } else if (scope === "alert_type") {
            behavior += `Applies to alert events with alert type ID or signature matching <code>${escapeHtml(target || "type")}</code>.`;
        }
        previewHtml += `<div style="margin-bottom: 0.5rem;">${behavior}</div>`;

        // 1.5 Describe action behavior
        let actionExplain = "";
        if (suppressed) {
            actionExplain = "Silences matching alerts completely (suppresses all notifications).";
        } else {
            actionExplain = "Keeps matching alerts active.";
            if (severity) {
                if (severity === "low") {
                    actionExplain += " Alert on Low and above (all alerts).";
                } else if (severity === "medium") {
                    actionExplain += " Alert only on Medium and High (Low alerts will be silenced).";
                } else if (severity === "high") {
                    actionExplain += " Alert only on High (Low and Medium alerts will be silenced).";
                }
            } else {
                actionExplain += " Alert on all severities (no minimum threshold).";
            }
        }
        previewHtml += `<div style="margin-bottom: 0.5rem; border-left: 2px solid var(--accent-color); padding-left: 0.5rem; font-style: italic; color: var(--text-secondary);">${actionExplain}</div>`;

        // 2. State precedence rank
        let rankText = "";
        let rankColor = "";
        if (scope === "ip") {
            rankText = "IP Scope (Priority 4/4 - Highest)";
            rankColor = "#10b981"; // green
        } else if (scope === "subnet") {
            rankText = "Subnet Scope (Priority 3/4 - High)";
            rankColor = "#38bdf8"; // sky blue
        } else if (scope === "alert_type") {
            rankText = "Alert Type Scope (Priority 2/4 - Medium)";
            rankColor = "#fb923c"; // orange
        } else {
            rankText = "Global Scope (Priority 1/4 - Lowest)";
            rankColor = "#94a3b8"; // slate
        }
        previewHtml += `<div style="margin-bottom: 0.5rem;"><strong>Precedence Rank:</strong> <span style="color: ${rankColor}; font-weight: 600;">${rankText}</span></div>`;

        // 3. Highlight overlap & conflict checks
        let conflicts = [];
        const currentId = inputPolicyId.value ? parseInt(inputPolicyId.value) : null;

        for (const other of policiesData) {
            if (other.id === currentId) continue;
            
            // Overlap check rules
            let overlaps = false;
            if (scope === "global" && other.scope === "global") {
                overlaps = true;
            } else if (scope === "ip" && other.scope === "ip" && target === other.target && target !== "") {
                overlaps = true;
            } else if (scope === "subnet" && other.scope === "subnet" && target === other.target && target !== "") {
                overlaps = true;
            } else if (scope === "alert_type" && other.scope === "alert_type" && target === other.target && target !== "") {
                overlaps = true;
            } else if (scope === "ip" && other.scope === "subnet" && target !== "" && other.target !== "") {
                overlaps = true;
            }

            if (overlaps) {
                let priorityExplain = "";
                let scopePriority = { "ip": 4, "subnet": 3, "alert_type": 2, "global": 1 };
                let myP = scopePriority[scope] || 0;
                let otherP = scopePriority[other.scope] || 0;

                if (myP > otherP) {
                    priorityExplain = `(This policy overrides "${escapeHtml(other.name)}")`;
                } else if (myP < otherP) {
                    priorityExplain = `(This policy is overridden by "${escapeHtml(other.name)}")`;
                } else {
                    priorityExplain = `(Identical scopes; first created rule matches or wins depending on db load order)`;
                }

                conflicts.push(`<li>Overlaps with <strong>${escapeHtml(other.name)}</strong> [${other.scope}] - <span style="font-style: italic;">${priorityExplain}</span></li>`);
            }
        }

        if (conflicts.length > 0) {
            previewHtml += `
                <div style="margin-top: 0.5rem; border-top: 1px solid var(--border-color); padding-top: 0.5rem;">
                    <strong class="text-warning">Overlapping Rules detected (${conflicts.length}):</strong>
                    <ul style="margin: 0.25rem 0 0 1rem; padding: 0; list-style-type: disc;">
                        ${conflicts.join('')}
                    </ul>
                </div>
            `;
        } else {
            previewHtml += `<div style="margin-top: 0.5rem; color: #10b981;">No active conflicts or overlapping policies.</div>`;
        }

        policyPrecedencePreview.innerHTML = previewHtml;
    }

    // Escape HTML helper
    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    async function savePolicySubmit(e) {
        e.preventDefault();
        const id = inputPolicyId.value;
        const name = inputPolicyName.value.trim();
        const scope = selectPolicyScope.value;
        const target = inputPolicyTarget.value.trim();
        const severityThreshold = selectPolicySeverityThreshold.value;
        const cooldownSeconds = parseInt(selectPolicyCooldown.value);
        const quietHoursStart = inputPolicyQuietHoursStart.value.trim();
        const quietHoursEnd = inputPolicyQuietHoursEnd.value.trim();
        const suppressed = inputPolicySuppressed.checked;

        // Gather channels
        const notificationChannels = [];
        document.querySelectorAll(".policy-channel-checkbox").forEach(cb => {
            if (cb.checked) notificationChannels.push(cb.value);
        });

        // Client-side validations
        if (!name) {
            showToast("Policy name is required", "error");
            return;
        }

        if (scope === "ip" && !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target)) {
            showToast("Target must be a valid IPv4 address", "error");
            return;
        }

        if (scope === "subnet" && !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/.test(target)) {
            showToast("Target must be a valid CIDR network block (e.g. 192.168.1.0/24)", "error");
            return;
        }

        if (scope === "alert_type" && !target) {
            showToast("Target alert type name is required", "error");
            return;
        }

        if (quietHoursStart && !/^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(quietHoursStart)) {
            showToast("Quiet Hours Start must match HH:MM format", "error");
            return;
        }

        if (quietHoursEnd && !/^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(quietHoursEnd)) {
            showToast("Quiet Hours End must match HH:MM format", "error");
            return;
        }

        const payload = {
            name,
            scope,
            target,
            severity_threshold: severityThreshold || null,
            cooldown_seconds: cooldownSeconds,
            quiet_hours_start: quietHoursStart || null,
            quiet_hours_end: quietHoursEnd || null,
            suppressed,
            notification_channels: notificationChannels
        };

        if (id) {
            payload.id = parseInt(id);
        }

        try {
            const method = id ? "PUT" : "POST";
            const url = id ? `/api/policies/${id}` : "/api/policies";
            const resp = await fetch(url, {
                method,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || "Save policy request failed");
            }

            const saved = await resp.json();
            showToast(`Policy "${saved.name}" saved successfully`);
            selectedPolicyId = saved.id;
            await fetchPolicies();
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    async function deletePolicyClick() {
        const id = inputPolicyId.value;
        if (!id) return;
        
        if (!confirm("Are you sure you want to delete this policy?")) {
            return;
        }

        try {
            const resp = await fetch(`/api/policies/${id}`, { method: "DELETE" });
            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || "Delete policy request failed");
            }
            showToast("Policy deleted successfully");
            selectedPolicyId = null;
            resetPolicyDetails();
            await fetchPolicies();
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    // Fetch Notification Rules
    async function fetchNotificationRules() {
        try {
            const resp = await fetch("/api/notification-rules");
            if (!resp.ok) throw new Error("Notification rules query failed");
            notificationRulesData = await resp.json();
            renderNotificationRules();
        } catch (err) {
            console.error("Error fetching notification rules: ", err);
        }
    }

    // Fetch Notification Logs
    async function fetchNotificationLogs() {
        try {
            const limit = selectNotificationLogsLimit ? selectNotificationLogsLimit.value : "25";
            const resp = await fetch(`/api/notification-logs?limit=${limit}`);
            if (!resp.ok) throw new Error("Notification logs query failed");
            notificationLogsData = await resp.json();
            renderNotificationLogs();
        } catch (err) {
            console.error("Error fetching notification logs: ", err);
        }
    }

    // Render Notification Rules Table
    function renderNotificationRules() {
        if (!tblNotificationRules) return;
        if (notificationRulesData.length === 0) {
            tblNotificationRules.innerHTML = `<tr><td colspan="7" class="text-center text-muted pad-large">No notification rules configured yet.</td></tr>`;
            return;
        }

        tblNotificationRules.innerHTML = notificationRulesData.map(r => {
            const isSelected = selectedNotificationRuleId === r.id;
            const enabledText = r.enabled 
                ? '<span class="badge badge-label text-success" style="background-color: rgba(16,185,129,0.1); border-color: rgba(16,185,129,0.2);">Enabled</span>' 
                : '<span class="badge badge-label text-muted" style="background-color: rgba(148,163,184,0.1); border-color: rgba(148,163,184,0.2);">Disabled</span>';
            const scopeBadge = `<span class="badge badge-label" style="background-color: rgba(56,189,248,0.1); border-color: rgba(56,189,248,0.2); color: #38bdf8; text-transform: uppercase;">${r.scope}</span>`;
            const channelsStr = (r.channel_targets || []).map(ch => {
                let color = "#94a3b8";
                if (ch === "slack") color = "#fb923c";
                if (ch === "telegram") color = "#38bdf8";
                if (ch === "webhook") color = "#a855f7";
                return `<span class="badge badge-label" style="background-color: rgba(255,255,255,0.05); color: ${color}; text-transform: uppercase; font-size: 0.7rem;">${ch}</span>`;
            }).join(" ");

            return `
                <tr data-id="${r.id}" class="${isSelected ? 'selected' : ''}" style="cursor: pointer;">
                    <td class="font-semibold">${escapeHtml(r.name)}</td>
                    <td>${enabledText}</td>
                    <td class="text-capitalize font-semibold">${escapeHtml(r.severity_min || "low")}</td>
                    <td>${scopeBadge}</td>
                    <td class="text-muted font-mono" style="font-size: 0.813rem;">${escapeHtml(r.target || "(all)")}</td>
                    <td>${channelsStr || '<span class="text-muted">—</span>'}</td>
                    <td class="text-center">
                        <button class="btn-secondary btn-select-rule" data-id="${r.id}">Select</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Listeners for selection
        tblNotificationRules.querySelectorAll("tr").forEach(row => {
            row.addEventListener("click", (e) => {
                if (e.target.tagName === "BUTTON") return;
                const id = parseInt(row.getAttribute("data-id"));
                selectNotificationRuleId(id);
            });
        });

        tblNotificationRules.querySelectorAll(".btn-select-rule").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const id = parseInt(e.target.getAttribute("data-id"));
                selectNotificationRuleId(id);
            });
        });
    }

    // Render Notification Logs
    function renderNotificationLogs() {
        if (!tblNotificationLogs) return;
        if (notificationLogsData.length === 0) {
            tblNotificationLogs.innerHTML = `<tr><td colspan="6" class="text-center text-muted pad-large">No notification audit logs found.</td></tr>`;
            return;
        }

        tblNotificationLogs.innerHTML = notificationLogsData.map(log => {
            const timestamp = formatTime(log.dispatched_at);
            const anomalyText = `IP: ${escapeHtml(log.anomaly_ip)} <span class="text-muted" style="font-size: 0.75rem;">(${escapeHtml(log.anomaly_type)})</span>`;
            const ruleName = log.rule_name ? escapeHtml(log.rule_name) : '<span class="text-muted font-italic">Default Fallback</span>';
            const channelBadge = `<span class="badge badge-label" style="text-transform: uppercase; font-size: 0.7rem;">${escapeHtml(log.channel)}</span>`;
            
            let statusBadge = "";
            if (log.status === "sent") {
                statusBadge = '<span class="badge-success">Sent</span>';
            } else if (log.status === "suppressed") {
                statusBadge = '<span class="badge-warning">Suppressed</span>';
            } else if (log.status === "deduplicated") {
                statusBadge = '<span class="badge-warning">Deduplicated</span>';
            } else if (log.status === "failed") {
                statusBadge = '<span class="badge-danger">Failed</span>';
            } else {
                statusBadge = `<span class="badge badge-label text-muted">${escapeHtml(log.status)}</span>`;
            }

            const infoText = log.error_message ? `<span class="text-danger" style="font-size: 0.75rem;">${escapeHtml(log.error_message)}</span>` : '<span class="text-muted font-italic">—</span>';

            return `
                <tr>
                    <td class="font-mono text-muted" style="font-size: 0.75rem;">${timestamp}</td>
                    <td>${anomalyText}</td>
                    <td class="font-semibold">${ruleName}</td>
                    <td>${channelBadge}</td>
                    <td>${statusBadge}</td>
                    <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(log.error_message || "")}">${infoText}</td>
                </tr>
            `;
        }).join('');
    }

    function selectNotificationRuleId(id) {
        selectedNotificationRuleId = id;
        const r = notificationRulesData.find(x => x.id === id);
        if (r) {
            selectNotificationRule(r);
        } else {
            resetNotificationRuleDetails();
        }
        renderNotificationRules();
    }

    function selectNotificationRule(r) {
        selectedNotificationRuleId = r.id;
        inputNotificationRuleId.value = r.id;
        inputNotificationRuleName.value = r.name;
        inputNotificationRuleEnabled.checked = r.enabled;
        selectNotificationRuleSeverity.value = r.severity_min || "low";
        inputNotificationRuleAlertTypes.value = (r.alert_types || []).join(", ");
        selectNotificationRuleScope.value = r.scope;
        inputNotificationRuleTarget.value = r.target || "";
        inputNotificationRuleCooldown.value = r.cooldown_seconds || "300";

        // Set channel checkboxes
        const channels = r.channel_targets || [];
        document.querySelectorAll(".rule-channel-checkbox").forEach(cb => {
            cb.checked = channels.includes(cb.value);
        });

        // Update labels and visibility
        updateNotificationTargetFieldVisibility();

        if (btnDeleteNotificationRule) btnDeleteNotificationRule.classList.remove("hidden");
        if (btnTestNotificationRule) btnTestNotificationRule.classList.remove("hidden");

        notificationDetailsTitle.textContent = `Edit Rule: ${r.name}`;
        notificationDetailsEmpty.classList.add("hidden");
        notificationDetailsContent.classList.remove("hidden");

        updateNotificationRulePreview();
    }

    function startAddNotificationRule() {
        selectedNotificationRuleId = "new";
        inputNotificationRuleId.value = "";
        inputNotificationRuleName.value = "";
        inputNotificationRuleEnabled.checked = true;
        selectNotificationRuleSeverity.value = "low";
        inputNotificationRuleAlertTypes.value = "";
        selectNotificationRuleScope.value = "global";
        inputNotificationRuleTarget.value = "";
        inputNotificationRuleCooldown.value = "300";

        document.querySelectorAll(".rule-channel-checkbox").forEach(cb => {
            cb.checked = false;
        });

        updateNotificationTargetFieldVisibility();

        if (btnDeleteNotificationRule) btnDeleteNotificationRule.classList.add("hidden");
        if (btnTestNotificationRule) btnTestNotificationRule.classList.add("hidden");

        notificationDetailsTitle.textContent = "New Notification Rule";
        notificationDetailsEmpty.classList.add("hidden");
        notificationDetailsContent.classList.remove("hidden");

        updateNotificationRulePreview();
        renderNotificationRules();
    }

    function resetNotificationRuleDetails() {
        selectedNotificationRuleId = null;
        if (notificationDetailsEmpty) notificationDetailsEmpty.classList.remove("hidden");
        if (notificationDetailsContent) notificationDetailsContent.classList.add("hidden");
    }

    function updateNotificationTargetFieldVisibility() {
        if (!selectNotificationRuleScope) return;
        const scope = selectNotificationRuleScope.value;
        if (scope === "global") {
            if (groupNotificationTarget) groupNotificationTarget.classList.add("hidden");
            if (inputNotificationRuleTarget) {
                inputNotificationRuleTarget.required = false;
                inputNotificationRuleTarget.value = "";
            }
        } else {
            if (groupNotificationTarget) groupNotificationTarget.classList.remove("hidden");
            if (inputNotificationRuleTarget) inputNotificationRuleTarget.required = true;
            if (scope === "ip" && labelNotificationTarget && inputNotificationRuleTarget) {
                labelNotificationTarget.innerHTML = 'Device IP Address <span class="text-danger">*</span>';
                inputNotificationRuleTarget.placeholder = "e.g. 192.168.1.50";
            } else if (scope === "subnet" && labelNotificationTarget && inputNotificationRuleTarget) {
                labelNotificationTarget.innerHTML = 'Subnet Range (CIDR) <span class="text-danger">*</span>';
                inputNotificationRuleTarget.placeholder = "e.g. 192.168.1.0/24";
            }
        }
    }

    function updateNotificationRulePreview() {
        if (!textNotificationRulePreview) return;
        const name = inputNotificationRuleName.value.trim() || "Unnamed Rule";
        const enabled = inputNotificationRuleEnabled.checked;
        const severity = selectNotificationRuleSeverity.value;
        const alertTypesStr = inputNotificationRuleAlertTypes.value.trim();
        const scope = selectNotificationRuleScope.value;
        const target = inputNotificationRuleTarget.value.trim();
        const cooldown = inputNotificationRuleCooldown.value;

        const channels = [];
        document.querySelectorAll(".rule-channel-checkbox").forEach(cb => {
            if (cb.checked) {
                let name = cb.value;
                if (name === "webhook") name = "Generic Webhook";
                if (name === "slack") name = "Slack/Discord Webhook";
                if (name === "telegram") name = "Telegram Bot";
                channels.push(`<strong>${name}</strong>`);
            }
        });

        if (!enabled) {
            textNotificationRulePreview.innerHTML = `<span style="color: var(--text-secondary);">This rule is currently <strong>disabled</strong> and will not process alerts.</span>`;
            return;
        }

        let scopeText = "all devices";
        if (scope === "ip" && target) {
            scopeText = `device <code>${escapeHtml(target)}</code>`;
        } else if (scope === "subnet" && target) {
            scopeText = `devices in subnet <code>${escapeHtml(target)}</code>`;
        }

        let typesText = "any anomaly type";
        if (alertTypesStr) {
            const types = alertTypesStr.split(",").map(t => `<code>${escapeHtml(t.trim())}</code>`).join(", ");
            typesText = `anomalies of type ${types}`;
        }

        let channelsText = "no active channels (it will be silenced)";
        if (channels.length > 0) {
            channelsText = channels.join(" and ");
        }

        let cooldownText = cooldown > 0 ? ` with a <strong>${cooldown}s</strong> cooldown` : " without cooldown";

        textNotificationRulePreview.innerHTML = `Alerts matching ${typesText} with severity <strong>&ge; ${escapeHtml(severity)}</strong> on ${scopeText} will be routed to ${channelsText}${cooldownText}.`;
    }

    async function saveNotificationRuleSubmit(e) {
        e.preventDefault();
        const id = inputNotificationRuleId.value;
        const name = inputNotificationRuleName.value.trim();
        const enabled = inputNotificationRuleEnabled.checked;
        const severityMin = selectNotificationRuleSeverity.value;
        const alertTypesVal = inputNotificationRuleAlertTypes.value.trim();
        const scope = selectNotificationRuleScope.value;
        const target = inputNotificationRuleTarget.value.trim();
        const cooldownSeconds = parseInt(inputNotificationRuleCooldown.value);

        // Gather channels
        const channelTargets = [];
        document.querySelectorAll(".rule-channel-checkbox").forEach(cb => {
            if (cb.checked) channelTargets.push(cb.value);
        });

        // Validations
        if (!name) {
            showToast("Rule name is required", "error");
            return;
        }

        if (scope === "ip" && !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target)) {
            showToast("Target must be a valid IPv4 address", "error");
            return;
        }

        if (scope === "subnet" && !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/.test(target)) {
            showToast("Target must be a valid CIDR network block (e.g. 192.168.1.0/24)", "error");
            return;
        }

        const alertTypes = alertTypesVal ? alertTypesVal.split(",").map(x => x.trim()).filter(Boolean) : [];

        const payload = {
            name,
            enabled,
            severity_min: severityMin,
            alert_types: alertTypes,
            scope,
            target,
            cooldown_seconds: cooldownSeconds,
            channel_targets: channelTargets
        };

        if (id) {
            payload.id = parseInt(id);
        }

        try {
            const method = id ? "PUT" : "POST";
            const url = id ? `/api/notification-rules/${id}` : "/api/notification-rules";
            const resp = await fetch(url, {
                method,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || "Save notification rule request failed");
            }

            const saved = await resp.json();
            showToast(`Notification rule "${saved.name}" saved successfully`);
            selectedNotificationRuleId = saved.id;
            await fetchNotificationRules();
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    async function deleteNotificationRuleClick() {
        const id = inputNotificationRuleId.value;
        if (!id) return;

        if (!confirm("Are you sure you want to delete this notification rule?")) {
            return;
        }

        try {
            const resp = await fetch(`/api/notification-rules/${id}`, { method: "DELETE" });
            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || "Delete notification rule request failed");
            }

            showToast("Notification rule deleted successfully");
            resetNotificationRuleDetails();
            await fetchNotificationRules();
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    async function testNotificationRuleClick() {
        const id = inputNotificationRuleId.value;
        if (!id) return;

        showToast("Sending test alert for rule...", "info");
        try {
            const resp = await fetch(`/api/notification-rules/${id}/test`, { method: "POST" });
            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || "Test notification rule request failed");
            }
            showToast("Test alert dispatched. Check your channels and audit log!");
            setTimeout(fetchNotificationLogs, 1500); // refresh audit logs shortly after send
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    // Render Device list to table
    function renderDevices() {
        const query = inputDeviceSearch.value.trim().toLowerCase();
        const filtered = devicesData.filter(dev => {
            return dev.ip.toLowerCase().includes(query) || 
                   (dev.hostname && dev.hostname.toLowerCase().includes(query)) ||
                   (dev.label && dev.label.toLowerCase().includes(query));
        });

        if (filtered.length === 0) {
            tblDevices.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No devices match active search filters.</td></tr>`;
            return;
        }

        tblDevices.innerHTML = filtered.map(dev => {
            const isSelected = selectedDeviceIP === dev.ip;
            return `
                <tr data-ip="${dev.ip}" class="${isSelected ? 'selected' : ''}">
                    <td class="font-semibold"><a href="#/devices/${dev.ip}" class="ip-link">${dev.ip}</a></td>
                    <td class="text-muted">${dev.hostname || "<i>Unresolved</i>"}</td>
                    <td>${dev.label ? `<span class="badge badge-label">${dev.label}</span>` : '<span class="text-muted">-</span>'}</td>
                    <td class="text-center">
                        <button class="btn-secondary btn-select-device" data-ip="${dev.ip}">Select</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Attach select click listeners to row and action button
        tblDevices.querySelectorAll("tr").forEach(row => {
            row.addEventListener("click", (e) => {
                if (e.target.tagName === "BUTTON" || e.target.tagName === "A") return;
                const ip = row.getAttribute("data-ip");
                window.location.hash = `#/devices/${ip}`;
            });
        });

        tblDevices.querySelectorAll(".btn-select-device").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const ip = e.target.getAttribute("data-ip");
                window.location.hash = `#/devices/${ip}`;
            });
        });
    }

    // Draw a simplified traffic timeline chart for the device using SVG
    function drawDeviceTrafficChart(timeSeries) {
        if (!deviceChartContainer) return;
        const width = 360;
        const height = 120;
        const pad = { top: 10, right: 12, bottom: 22, left: 52 };
        const plotW = width - pad.left - pad.right;
        const plotH = height - pad.top - pad.bottom;
        deviceChartContainer.innerHTML = "";

        const points = (timeSeries || []).map(item => ({
            ts: new Date(item.bucket_ts).getTime(),
            value: Number(item.bytes || 0),
            raw: item
        })).filter(item => Number.isFinite(item.ts));

        if (points.length === 0) {
            deviceChartContainer.innerHTML = `<span class="text-muted" style="font-size: 0.813rem;">No traffic data recorded</span>`;
            return;
        }

        const minTs = Math.min(...points.map(p => p.ts));
        const maxTs = Math.max(...points.map(p => p.ts));
        const maxValue = Math.max(...points.map(p => p.value), 1);
        const tsSpan = Math.max(maxTs - minTs, 1);
        const xFor = ts => pad.left + ((ts - minTs) / tsSpan) * plotW;
        const yFor = value => pad.top + plotH - (value / maxValue) * plotH;

        // Draw simplified horizontal grid lines (3 lines: min, mid, max)
        const gridLines = [0, 0.5, 1].map(frac => {
            const y = pad.top + plotH - (frac * plotH);
            const label = formatBytes(maxValue * frac);
            return `<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" class="chart-grid" style="stroke: var(--border-color); stroke-dasharray: 2 2;"></line>
                    <text x="${pad.left - 6}" y="${y + 3}" text-anchor="end" class="chart-axis" style="font-size: 0.65rem;">${label}</text>`;
        }).join("");

        const pathData = points.map((p, idx) => `${idx === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yFor(p.value).toFixed(2)}`).join(" ");
        const areaData = `${pathData} L ${xFor(points[points.length - 1].ts).toFixed(2)} ${pad.top + plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top + plotH} Z`;
        
        const firstLabel = formatShortTime(new Date(minTs));
        const lastLabel = formatShortTime(new Date(maxTs));

        const svgContent = `
            <svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" style="overflow: visible;">
                <defs>
                    <linearGradient id="deviceAreaFill" x1="0" x2="0" y1="0" y2="1">
                        <stop offset="0%" stop-color="var(--primary-color)" stop-opacity="0.15"></stop>
                        <stop offset="100%" stop-color="var(--primary-color)" stop-opacity="0.01"></stop>
                    </linearGradient>
                </defs>
                ${gridLines}
                <path d="${areaData}" fill="url(#deviceAreaFill)"></path>
                <path d="${pathData}" class="chart-line" style="stroke: var(--primary-color); stroke-width: 1.5; fill: none;"></path>
                ${points.map(p => `<circle cx="${xFor(p.ts).toFixed(2)}" cy="${yFor(p.value).toFixed(2)}" r="2" class="chart-point" style="stroke: var(--primary-color);"><title>${new Date(p.raw.bucket_ts).toLocaleTimeString()} - Bytes: ${formatBytes(p.value)}</title></circle>`).join("")}
                <text x="${pad.left}" y="${height - 4}" class="chart-axis" style="font-size: 0.65rem;">${firstLabel}</text>
                <text x="${width - pad.right}" y="${height - 4}" text-anchor="end" class="chart-axis" style="font-size: 0.65rem;">${lastLabel}</text>
            </svg>
        `;
        deviceChartContainer.innerHTML = svgContent;
    }

    // Select device and load profile details
    async function selectDevice(ip) {
        selectedDeviceIP = ip;
        renderDevices(); // Highlight row
        
        detailsEmpty.classList.add("hidden");
        detailsContent.classList.remove("hidden");
        
        detailIp.textContent = ip;
        detailHost.textContent = "Loading device profile...";
        detailSubnet.textContent = "-";
        detailFirstSeen.textContent = "-";
        detailLastSeen.textContent = "-";
        detailRiskBadgeContainer.innerHTML = "";
        if (detailRiskExplanationSection) detailRiskExplanationSection.classList.add("hidden");
        if (detailRiskExplanationContent) detailRiskExplanationContent.innerHTML = "";
        deviceChartContainer.innerHTML = `<span class="text-muted" style="font-size: 0.813rem;">Loading timeline...</span>`;
        tblDevicePeers.innerHTML = `<tr><td colspan="2" class="text-muted text-center" style="font-size: 0.75rem;">Loading peers...</td></tr>`;
        tblDevicePorts.innerHTML = `<tr><td colspan="2" class="text-muted text-center" style="font-size: 0.75rem;">Loading ports...</td></tr>`;
        deviceAlertsList.innerHTML = `<div class="text-muted text-center" style="font-size: 0.813rem; padding: 0.5rem;">Loading alerts...</div>`;
        baselineStatsContent.innerHTML = `<p class="text-muted text-center">Loading baseline profile...</p>`;

        btnDeviceFwRules.onclick = () => {
            openFirewallModal(ip);
        };

        // 1. Fetch Profile details
        try {
            const resp = await fetch(`/api/devices/${ip}`);
            if (!resp.ok) throw new Error("Failed fetching device profile");
            const profile = await resp.json();

            detailHost.textContent = profile.hostname ? `Reverse DNS: ${profile.hostname}` : "Reverse DNS: Unresolved";
            inputDetailLabel.value = profile.label || "";
            detailSubnet.textContent = profile.subnet_vlan || "Unknown";
            detailFirstSeen.textContent = profile.first_seen ? formatTime(profile.first_seen) : "-";
            detailLastSeen.textContent = profile.last_seen ? formatTime(profile.last_seen) : "-";

            const riskInfo = profile.risk || { risk_score: 0, risk_level: "low", active_alert_count: 0 };
            const badgeClass = riskInfo.risk_level === "high" ? "risk-badge-high" : (riskInfo.risk_level === "medium" ? "risk-badge-medium" : "risk-badge-low");
            detailRiskBadgeContainer.innerHTML = `<span class="risk-badge ${badgeClass}" title="Active alerts: ${riskInfo.active_alert_count}">Risk Index: ${riskInfo.risk_score}</span>`;

            // Render Risk Index Explanation
            if (riskInfo.breakdown && (riskInfo.breakdown.alert_breakdown || []).length > 0) {
                if (detailRiskExplanationSection && detailRiskExplanationContent) {
                    const bd = riskInfo.breakdown;
                    
                    let html = `
                        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 0.5rem; margin-bottom: 0.5rem;">
                            <span><strong>Calculated Score:</strong> <span class="risk-badge ${badgeClass}" style="padding: 0.15rem 0.4rem; font-size: 0.75rem; border-radius: 4px; vertical-align: middle;">${riskInfo.risk_score}</span></span>
                            <span class="text-muted" style="text-transform: capitalize;"><strong>Level:</strong> ${riskInfo.risk_level}</span>
                        </div>
                        <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                    `;

                    // Add alert contributors
                    (bd.alert_breakdown || []).forEach(c => {
                        const ageMinStr = Math.round(c.age_hours * 60);
                        let ageText = "";
                        if (ageMinStr < 60) {
                            ageText = `${ageMinStr} minutes ago`;
                        } else {
                            const ageHoursRounded = (c.age_hours).toFixed(1);
                            ageText = `${ageHoursRounded} hours ago`;
                        }

                        const percentDecay = Math.round(c.decay_factor * 100);

                        html += `
                            <div style="background: rgba(255,255,255,0.01); border: 1px solid var(--border-color); padding: 0.5rem; border-radius: 6px;">
                                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.25rem;">
                                    <span class="font-semibold" style="font-size: 0.8rem;">${escapeHtml(c.type)}</span>
                                    <span class="badge ${c.severity === "high" ? 'badge-high' : (c.severity === "medium" ? 'badge-medium' : 'badge-low')}" style="font-size: 0.65rem; padding: 0.1rem 0.3rem;">${c.severity}</span>
                                </div>
                                <p style="margin: 0 0 0.4rem 0; font-size: 0.78rem; line-height: 1.35; color: var(--text-primary);">${escapeHtml(c.description)}</p>
                                <div class="text-muted" style="display: flex; justify-content: space-between; align-items: center; font-size: 0.7rem; border-top: 1px dashed var(--border-color); padding-top: 0.25rem;">
                                    <span>Triggered: <strong>${ageText}</strong></span>
                                    <span>Formula: <code>${c.base_weight} (base) &times; ${percentDecay}% (decay) = +${c.contribution.toFixed(1)} pts</code></span>
                                </div>
                            </div>
                        `;
                    });

                    // Add correlation boost
                    if (bd.correlation_boost > 0) {
                        html += `
                            <div style="background: rgba(251,146,60,0.05); border: 1px solid rgba(251,146,60,0.2); padding: 0.5rem; border-radius: 6px; color: #fb923c;">
                                <div class="font-semibold" style="font-size: 0.8rem; margin-bottom: 0.15rem;">Correlation Boost Applied</div>
                                <p style="margin: 0; font-size: 0.75rem; line-height: 1.3;">Correlated signature-based IDS alert (Suricata) with flow-based anomaly within 1 hour (+${bd.correlation_boost} boost)</p>
                            </div>
                        `;
                    }

                    // Add classification threshold explanations
                    html += `
                        </div>
                        <div style="border-top: 1px solid var(--border-color); padding-top: 0.5rem; margin-top: 0.25rem; display: flex; justify-content: space-between; font-size: 0.7rem; color: var(--text-secondary);">
                            <span>Thresholds:</span>
                            <span>Low: &lt; 30</span>
                            <span>Medium: 30 - 69</span>
                            <span>High: &ge; 70</span>
                        </div>
                    `;

                    detailRiskExplanationContent.innerHTML = html;
                    detailRiskExplanationSection.classList.remove("hidden");
                }
            } else {
                if (detailRiskExplanationSection) detailRiskExplanationSection.classList.add("hidden");
            }

            // Populate baseline stats
            if (profile.baseline) {
                const baseline = profile.baseline;
                const byteLimit = baseline.mean_bytes + (3 * baseline.stddev_bytes);
                const packetLimit = baseline.mean_packets + (3 * baseline.stddev_packets);
                const peerLimit = baseline.mean_peers + (3 * baseline.stddev_peers);

                baselineStatsContent.innerHTML = `
                    <div class="baseline-stat-row">
                        <span class="metric-name">Average Bytes/Min</span>
                        <span class="metric-value">${formatBytes(baseline.mean_bytes)}</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Traffic Limit (Mean + 3σ)</span>
                        <span class="metric-value text-warning" style="font-weight:700;">${formatBytes(byteLimit)}</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Average Packets/Min</span>
                        <span class="metric-value">${formatNumber(Math.round(baseline.mean_packets))} pkts</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Packet Limit (Mean + 3σ)</span>
                        <span class="metric-value text-warning" style="font-weight:700;">${formatNumber(Math.round(packetLimit))} pkts</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Average Peers/Min</span>
                        <span class="metric-value">${baseline.mean_peers.toFixed(1)}</span>
                    </div>
                    <div class="baseline-stat-row">
                        <span class="metric-name">Peer Limit (Mean + 3σ)</span>
                        <span class="metric-value text-warning" style="font-weight:700;">${Math.round(peerLimit)} peers</span>
                    </div>
                    <p class="text-muted text-right" style="font-size:0.75rem; margin-top:0.5rem;">
                        Baseline updated: ${formatTime(baseline.updated_at)}
                    </p>
                `;
            } else {
                baselineStatsContent.innerHTML = `
                    <div class="text-center text-muted pad-large" style="border: 1px dashed rgba(255,255,255,0.08); border-radius: 8px;">
                        No baseline computed yet.<br>
                        <span style="font-size: 0.75rem;">Profile will generate once at least 5 minutes of active traffic flows are aggregated.</span>
                    </div>
                `;
            }

            // Populate device alerts history
            if (profile.anomalies && profile.anomalies.length > 0) {
                deviceAlertsList.innerHTML = profile.anomalies.map(anom => {
                    const statusClass = `status-${anom.status}`;
                    const badgeClass = anom.severity === "high" ? "badge-high" : (anom.severity === "medium" ? "badge-medium" : "badge-low");
                    return `
                        <div class="device-alert-item sev-${anom.severity}">
                            <div style="flex-grow: 1; margin-right: 0.5rem;">
                                <div style="display: flex; gap: 0.4rem; align-items: center; margin-bottom: 0.15rem;">
                                    <span class="badge ${badgeClass}" style="font-size: 0.65rem; padding: 0.1rem 0.25rem;">${anom.type}</span>
                                    <span class="${statusClass}" style="font-size: 0.65rem; padding: 0.1rem 0.25rem;">${anom.status}</span>
                                </div>
                                <div style="font-weight: 500; font-size: 0.75rem; color: var(--text-primary); margin-bottom: 0.15rem;">${anom.description}</div>
                                <div class="text-muted" style="font-size: 0.65rem;">${new Date(anom.created_at).toLocaleString()}</div>
                            </div>
                            <div class="device-alert-actions" style="display: flex; gap: 0.25rem; flex-shrink: 0;">
                                ${anom.status === 'active' ?
                                    `<button class="btn-secondary btn-device-alert-triage" data-id="${anom.id}" data-action="acknowledged" style="font-size: 0.65rem; padding: 0.2rem 0.4rem;">Ack</button>
                                     <button class="btn-secondary btn-device-alert-triage" data-id="${anom.id}" data-action="silenced" style="font-size: 0.65rem; padding: 0.2rem 0.4rem;">Silence</button>` :
                                    `<button class="btn-secondary btn-device-alert-triage" data-id="${anom.id}" data-action="active" style="font-size: 0.65rem; padding: 0.2rem 0.4rem;">Reactivate</button>`
                                }
                            </div>
                        </div>
                    `;
                }).join('');

                // Bind click handlers to triage buttons inside alerts list
                deviceAlertsList.querySelectorAll(".btn-device-alert-triage").forEach(btn => {
                    btn.addEventListener("click", async (e) => {
                        const id = btn.getAttribute("data-id");
                        const action = btn.getAttribute("data-action");
                        await updateAnomalyStatus(id, action);
                        selectDevice(ip);
                    });
                });
            } else {
                deviceAlertsList.innerHTML = `
                    <div class="text-muted text-center" style="font-size: 0.813rem; padding: 0.5rem; border: 1px dashed var(--border-color); border-radius: 6px;">
                        No alerts history
                    </div>
                `;
            }

            // Populate applied policies
            if (devicePoliciesList) {
                const polSummary = profile.policy_summary || {};
                const matchingPolicies = polSummary.policies || [];
                if (matchingPolicies.length > 0) {
                    devicePoliciesList.innerHTML = matchingPolicies.map(p => {
                        const statusClass = p.suppressed ? "status-silenced" : "status-active";
                        const statusText = p.suppressed ? "Silenced" : "Active";
                        const badgeClass = p.scope === "ip" ? "badge-high" : (p.scope === "subnet" ? "badge-medium" : "badge-low");
                        return `
                            <div class="device-alert-item" style="border-left: 3px solid var(--accent-color); padding: 0.4rem 0.6rem; display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;">
                                <div style="flex-grow: 1;">
                                    <div style="display: flex; gap: 0.4rem; align-items: center; margin-bottom: 0.15rem;">
                                        <span class="badge ${badgeClass}" style="font-size: 0.65rem; padding: 0.1rem 0.25rem;">${p.scope}</span>
                                        <span style="font-size: 0.65rem; color: var(--text-muted); font-family: monospace;">${escapeHtml(p.target || "global")}</span>
                                    </div>
                                    <div style="font-weight: 600; font-size: 0.75rem; color: var(--text-primary);">${escapeHtml(p.name)}</div>
                                </div>
                                <div style="flex-shrink: 0; font-size: 0.7rem; font-weight: 600; text-transform: uppercase;" class="${statusClass}">
                                    ${statusText}
                                </div>
                            </div>
                        `;
                    }).join('');
                } else {
                    devicePoliciesList.innerHTML = `
                        <div class="text-muted text-center" style="font-size: 0.813rem; padding: 0.5rem; border: 1px dashed var(--border-color); border-radius: 6px;">
                            No applied policies
                        </div>
                    `;
                }
            }

        } catch (err) {
            console.error("Error loading device profile context: ", err);
            detailHost.textContent = "Error loading profile details";
        }

        // 2. Fetch flows time series, peers and destination ports
        try {
            const range = trafficRangeConfig();
            const params = new URLSearchParams({
                start: range.start.toISOString(),
                end: range.end.toISOString(),
                bucket: range.bucket.toString(),
                limit: "10"
            });

            const resp = await fetch(`/api/devices/${ip}/flows?${params.toString()}`);
            if (!resp.ok) throw new Error("Failed fetching flows details");
            const flowsData = await resp.json();

            // Populate Top Peers
            if (flowsData.top_peers && flowsData.top_peers.length > 0) {
                tblDevicePeers.innerHTML = flowsData.top_peers.map(peer => {
                    return `
                        <tr>
                            <td class="font-semibold"><a href="#/devices/${peer.key}" class="ip-link">${peer.key}</a></td>
                            <td>${formatBytes(peer.value)}</td>
                        </tr>
                    `;
                }).join('');
            } else {
                tblDevicePeers.innerHTML = `<tr><td colspan="2" class="text-muted text-center" style="font-size: 0.75rem;">No active peers in this range</td></tr>`;
            }

            // Populate Top Destination Ports
            if (flowsData.top_ports && flowsData.top_ports.length > 0) {
                tblDevicePorts.innerHTML = flowsData.top_ports.map(port => {
                    return `
                        <tr>
                            <td class="font-semibold">Port ${port.key}</td>
                            <td>${formatBytes(port.value)}</td>
                        </tr>
                    `;
                }).join('');
            } else {
                tblDevicePorts.innerHTML = `<tr><td colspan="2" class="text-muted text-center" style="font-size: 0.75rem;">No active ports in this range</td></tr>`;
            }

            // Draw SVG chart
            drawDeviceTrafficChart(flowsData.time_series);

        } catch (err) {
            console.error("Error loading device traffic timeline/flows: ", err);
            deviceChartContainer.innerHTML = `<span class="text-danger" style="font-size: 0.813rem;">Failed to load traffic history</span>`;
        }
    }

    // Submit label update from details panel
    formUpdateLabel.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!selectedDeviceIP) return;

        const newLabel = inputDetailLabel.value.trim();

        try {
            const resp = await fetch(`/api/devices/${selectedDeviceIP}/label`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ label: newLabel })
            });

            if (!resp.ok) throw new Error("Failed to update device label");

            showToast(`Label updated for ${selectedDeviceIP}.`);
            await fetchDevices();
            selectDevice(selectedDeviceIP);
        } catch (err) {
            showToast(err.message, "error");
        }
    });

    // Select an anomaly to view details in the right pane
    function selectAnomaly(id) {
        selectedAnomalyId = id.toString();
        renderAnomalies(); // Highlight selected row

        const anom = anomaliesData.find(a => a.id.toString() === selectedAnomalyId);
        if (!anom) return;

        anomalyDetailsEmpty.classList.add("hidden");
        anomalyDetailsContent.classList.remove("hidden");

        anomalyDetailIp.textContent = anom.ip;
        anomalyDetailType.textContent = anom.type;
        anomalyDetailDescription.textContent = anom.description;
        anomalyDetailTime.textContent = new Date(anom.created_at).toLocaleString();
        anomalyDetailStatus.textContent = anom.status;
        anomalyDetailStatus.className = `badge-label status-${anom.status}`;

        // Populate severity badge
        const badgeClass = anom.severity === "high" ? "badge-high" : (anom.severity === "medium" ? "badge-medium" : "badge-low");
        anomalyDetailBadgeContainer.innerHTML = `<span class="badge ${badgeClass}">${anom.severity.toUpperCase()}</span>`;

        // Populate action buttons based on status
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

        // Bind click events on triage buttons inside the details pane
        anomalyDetailActions.querySelectorAll(".btn-triage").forEach(btn => {
            btn.addEventListener("click", async (e) => {
                const action = btn.getAttribute("data-action");
                await updateAnomalyStatus(anom.id, action);
            });
        });

        anomalyDetailActions.querySelectorAll(".btn-block-rules").forEach(btn => {
            btn.addEventListener("click", () => {
                openFirewallModal(anom.ip);
            });
        });
    }

    // Render Anomalies to table
    function renderAnomalies() {
        const searchQuery = document.getElementById("search-anomalies").value.toLowerCase().trim();
        const severityFilter = document.getElementById("filter-anomalies-severity").value;

        const filtered = anomaliesData.filter(anom => {
            // 1. Triage Status Tab filter
            if (activeTriageFilter !== "all" && anom.status !== activeTriageFilter) return false;
            // 2. Severity filter
            if (severityFilter !== "all" && anom.severity !== severityFilter) return false;
            // 3. Search query filter
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
            const isSelected = selectedAnomalyId === anom.id.toString();
            
            return `
                <tr class="anomaly-row ${isSelected ? 'selected' : ''}" data-id="${anom.id}" style="cursor: pointer;">
                    <td class="font-semibold"><a href="#/devices/${anom.ip}" class="ip-link">${anom.ip}</a></td>
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

        // Attach select click listeners to row and select button
        tblAnomalies.querySelectorAll("tr").forEach(row => {
            row.addEventListener("click", (e) => {
                if (e.target.tagName === "BUTTON") return;
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

    // Submit triage action PUT request
    async function updateAnomalyStatus(id, newStatus) {
        try {
            const resp = await fetch(`/api/anomalies/${id}/status`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ status: newStatus })
            });

            if (!resp.ok) throw new Error("Failed to update alert status");

            showToast(`Alert status updated to ${newStatus}.`);
            await Promise.all([
                fetchAnomalies(),
                fetchThreatRisk()
            ]);
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    // Fetch system audit logs from API
    let auditLogsData = [];
    async function fetchAuditLogs() {
        try {
            const resp = await fetch("/api/audit-logs?limit=100");
            if (!resp.ok) throw new Error("Failed to query audit logs");
            auditLogsData = await resp.json();
            renderAuditLogs();
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    // Render audit logs into UI table
    function renderAuditLogs() {
        const tblAuditLogs = document.getElementById("tbl-audit-logs").querySelector("tbody");
        if (!tblAuditLogs) return;

        const searchQuery = document.getElementById("search-audit-logs").value.toLowerCase().trim();

        // 1. Filter
        const filtered = auditLogsData.filter(log => {
            if (searchQuery === "") return true;
            return log.action.toLowerCase().includes(searchQuery) || log.details.toLowerCase().includes(searchQuery);
        });

        // 2. Paginate
        const total = filtered.length;
        const totalPages = Math.ceil(total / auditLogPageSize) || 1;
        
        if (auditLogPage >= totalPages) {
            auditLogPage = totalPages - 1;
        }
        if (auditLogPage < 0) {
            auditLogPage = 0;
        }

        const startIdx = auditLogPage * auditLogPageSize;
        const endIdx = Math.min(startIdx + auditLogPageSize, total);
        const pageData = filtered.slice(startIdx, endIdx);

        // Update stats text
        const statsEl = document.getElementById("audit-pagination-stats");
        if (statsEl) {
            if (total === 0) {
                statsEl.textContent = "Showing 0-0 of 0 logs";
            } else {
                statsEl.textContent = `Showing ${startIdx + 1}-${endIdx} of ${total} logs`;
            }
        }

        // Update pagination buttons state
        const btnPrev = document.getElementById("btn-audit-prev");
        const btnNext = document.getElementById("btn-audit-next");
        if (btnPrev) btnPrev.disabled = (auditLogPage === 0);
        if (btnNext) btnNext.disabled = (auditLogPage >= totalPages - 1);

        if (pageData.length === 0) {
            tblAuditLogs.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No audit logs match filters.</td></tr>`;
            return;
        }

        tblAuditLogs.innerHTML = pageData.map(log => `
            <tr>
                <td style="white-space: nowrap;">${new Date(log.timestamp).toLocaleString()}</td>
                <td><span class="badge badge-label">${log.action}</span></td>
                <td>${log.details}</td>
            </tr>
        `).join("");
    }

    // Modal Firewall logic
    let firewallTemplates = null;
    let activeFwTab = "mikrotik";

    async function openFirewallModal(ip) {
        const modal = document.getElementById("modal-firewall");
        const targetIpField = document.getElementById("firewall-target-ip");
        const codeContent = document.getElementById("firewall-code-content");
        
        targetIpField.value = ip;
        codeContent.textContent = "Loading rules...";
        activeFwTab = "mikrotik";
        
        // Reset tab active state in modal
        document.querySelectorAll(".fw-tab-btn").forEach(btn => {
            if (btn.getAttribute("data-fw") === "mikrotik") {
                btn.classList.add("active");
            } else {
                btn.classList.remove("active");
            }
        });

        modal.showModal();

        try {
            const resp = await fetch(`/api/firewall/rules?ip=${ip}`);
            if (!resp.ok) throw new Error("Failed to load firewall templates");
            firewallTemplates = await resp.json();
            renderFirewallCode();
        } catch (err) {
            codeContent.textContent = `Error: ${err.message}`;
            showToast(err.message, "error");
        }
    }

    function renderFirewallCode() {
        const codeContent = document.getElementById("firewall-code-content");
        if (!firewallTemplates) return;
        codeContent.textContent = firewallTemplates[activeFwTab] || "No template configured.";
    }

    // Setup modal button handlers
    const btnCloseModal = document.getElementById("btn-close-modal");
    if (btnCloseModal) {
        btnCloseModal.addEventListener("click", () => {
            document.getElementById("modal-firewall").close();
        });
    }

    const btnCopyRules = document.getElementById("btn-copy-rules");
    if (btnCopyRules) {
        btnCopyRules.addEventListener("click", () => {
            const code = document.getElementById("firewall-code-content").textContent;
            navigator.clipboard.writeText(code).then(() => {
            showToast("Rules copied.");
            }).catch(err => {
                showToast("Copy failed: " + err, "error");
            });
        });
    }

    document.querySelectorAll(".fw-tab-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            document.querySelectorAll(".fw-tab-btn").forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeFwTab = e.target.getAttribute("data-fw");
            renderFirewallCode();
        });
    });

    // Perform full page data fetch
    async function loadData() {
        const refreshIcon = btnRefresh ? btnRefresh.querySelector("svg") : null;
        if (btnRefresh) {
            btnRefresh.disabled = true;
            if (refreshIcon) refreshIcon.classList.add("icon-spin");
        }
        try {
            // Fetch health unconditionally so status indicator updates on every view
            await fetchHealth();

            // Fetch threat risk ranks unconditionally as they affect indicators and badges across multiple views
            await fetchThreatRisk();

            if (activeView === "dashboard") {
                await Promise.all([
                    fetchExporters(),
                    fetchTopTalkers(),
                    fetchDevices(),
                    fetchAnomalies(),
                    fetchTrafficTimeSeries()
                ]);
                renderNetworkSignals();
            } else if (activeView === "devices") {
                await fetchDevices();
                if (selectedDeviceIP) {
                    const dev = devicesData.find(d => d.ip === selectedDeviceIP);
                    if (dev) {
                        selectDevice(selectedDeviceIP);
                    }
                }
            } else if (activeView === "anomalies") {
                await fetchAnomalies();
            } else if (activeView === "policies") {
                await fetchPolicies();
                if (selectedPolicyId !== null) {
                    const p = policiesData.find(x => x.id === selectedPolicyId);
                    if (p) {
                        selectPolicy(p);
                    } else {
                        resetPolicyDetails();
                    }
                }
            } else if (activeView === "notifications") {
                await Promise.all([
                    fetchNotificationRules(),
                    fetchNotificationLogs()
                ]);
                if (selectedNotificationRuleId !== null) {
                    const r = notificationRulesData.find(x => x.id === selectedNotificationRuleId);
                    if (r) {
                        selectNotificationRule(r);
                    } else {
                        resetNotificationRuleDetails();
                    }
                }
            } else if (activeView === "audit") {
                await fetchAuditLogs();
            } else if (activeView === "settings") {
                await fetchSettings();
            }
        } finally {
            if (btnRefresh) {
                btnRefresh.disabled = false;
                if (refreshIcon) refreshIcon.classList.remove("icon-spin");
            }
        }
    }

    // Switch between SPA views
    function parseHashRoute() {
        const hash = window.location.hash || "#/traffic";
        if (hash.startsWith("#/devices/")) {
            const ip = hash.substring("#/devices/".length);
            return { viewName: "devices", ip: ip };
        }
        const viewName = routeViews[hash] || "dashboard";
        return { viewName, ip: null };
    }

    function switchView(viewName, ip = null) {
        // Check unsaved changes before switching view
        const hasUnsaved = Object.keys(unsavedChanges).some(k => unsavedChanges[k]);
        if (hasUnsaved && viewName !== "settings") {
            if (!confirm("You have unsaved changes in Settings. Do you want to discard them?")) {
                // Revert hash back to settings route
                window.location.hash = "#/settings";
                return;
            }
            // User confirmed discard: clear unsaved states
            Object.keys(unsavedChanges).forEach(k => markUnsaved(k, false));
        }

        activeView = viewName;
        if (ip) {
            selectedDeviceIP = ip;
        }
        const targetHash = ip ? `#/devices/${ip}` : viewRoutes[viewName];
        if (targetHash && window.location.hash !== targetHash) {
            window.location.hash = targetHash;
        }

        const titles = {
            dashboard: ["Traffic", "Flow telemetry, risk signals, and local device activity"],
            devices: ["Devices", "Local inventory, labels, and learned baselines"],
            anomalies: ["Alerts", "Behavior changes that need review"],
            policies: ["Policies", "Define custom treatment rules for devices and alerts"],
            notifications: ["Notifications", "Route alerts by severity, type, and IP/subnet target"],
            audit: ["Audit", "Configuration changes and alert review history"],
            settings: ["Settings", "Runtime configuration for this FlowGuard node"]
        };
        const title = titles[viewName] || titles.dashboard;
        if (workspaceTitle) workspaceTitle.textContent = title[0];
        if (workspaceSubtitle) workspaceSubtitle.textContent = title[1];
        
        // Remove active class from all nav links
        if (navDashboard) navDashboard.classList.remove("active");
        if (navDevices) navDevices.classList.remove("active");
        if (navAnomalies) navAnomalies.classList.remove("active");
        if (navPolicies) navPolicies.classList.remove("active");
        if (navNotifications) navNotifications.classList.remove("active");
        if (navAudit) navAudit.classList.remove("active");
        if (navSettings) navSettings.classList.remove("active");

        // Hide all views
        if (viewDashboard) viewDashboard.classList.remove("active");
        if (viewDevices) viewDevices.classList.remove("active");
        if (viewAnomalies) viewAnomalies.classList.remove("active");
        if (viewPolicies) viewPolicies.classList.remove("active");
        if (viewNotifications) viewNotifications.classList.remove("active");
        if (viewAudit) viewAudit.classList.remove("active");
        if (viewSettings) viewSettings.classList.remove("active");

        if (viewName === "dashboard") {
            if (navDashboard) navDashboard.classList.add("active");
            if (viewDashboard) viewDashboard.classList.add("active");
        } else if (viewName === "devices") {
            if (navDevices) navDevices.classList.add("active");
            if (viewDevices) viewDevices.classList.add("active");
        } else if (viewName === "anomalies") {
            if (navAnomalies) navAnomalies.classList.add("active");
            if (viewAnomalies) viewAnomalies.classList.add("active");
        } else if (viewName === "policies") {
            if (navPolicies) navPolicies.classList.add("active");
            if (viewPolicies) viewPolicies.classList.add("active");
        } else if (viewName === "notifications") {
            if (navNotifications) navNotifications.classList.add("active");
            if (viewNotifications) viewNotifications.classList.add("active");
        } else if (viewName === "audit") {
            if (navAudit) navAudit.classList.add("active");
            if (viewAudit) viewAudit.classList.add("active");
        } else if (viewName === "settings") {
            if (navSettings) navSettings.classList.add("active");
            if (viewSettings) viewSettings.classList.add("active");
        }
        
        loadData();
    }

    // Navigation Button Listeners
    if (navDashboard) navDashboard.addEventListener("click", () => { window.location.hash = "#/traffic"; });
    if (navDevices) navDevices.addEventListener("click", () => { window.location.hash = "#/devices"; });
    if (navAnomalies) navAnomalies.addEventListener("click", () => { window.location.hash = "#/alerts"; });
    if (navPolicies) navPolicies.addEventListener("click", () => { window.location.hash = "#/policies"; });
    if (navNotifications) navNotifications.addEventListener("click", () => { window.location.hash = "#/notifications"; });
    if (navAudit) navAudit.addEventListener("click", () => { window.location.hash = "#/audit"; });
    if (navSettings) navSettings.addEventListener("click", () => { window.location.hash = "#/settings"; });

    // Handle URL Hash changes
    window.addEventListener("hashchange", () => {
        const route = parseHashRoute();
        switchView(route.viewName, route.ip);
    });

    // Handle Manual Refresh
    btnRefresh.addEventListener("click", () => {
        loadData();
    });

    function applyStoredShellPreferences() {
        const sidebarCollapsed = localStorage.getItem("fg_sidebar_collapsed") === "true";
        const darkMode = localStorage.getItem("fg_theme") === "dark";

        document.body.classList.toggle("sidebar-collapsed", sidebarCollapsed);
        document.body.classList.toggle("dark-mode", darkMode);

        if (btnToggleSidebar) {
            const toolText = btnToggleSidebar.querySelector(".tool-text");
            if (toolText) {
                toolText.textContent = sidebarCollapsed ? "Expand" : "Collapse";
            }
            btnToggleSidebar.setAttribute("title", sidebarCollapsed ? "Expand Sidebar" : "Collapse Sidebar");
        }

        updateThemeButtons(darkMode);
    }

    function updateThemeButtons(darkMode) {
        themeButtons.forEach(btn => {
            const toolText = btn.querySelector(".tool-text");
            if (toolText) {
                toolText.textContent = darkMode ? "Light Mode" : "Dark Mode";
            }
            const svg = btn.querySelector("svg");
            if (svg) {
                if (darkMode) {
                    svg.innerHTML = `<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>`;
                } else {
                    svg.innerHTML = `<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>`;
                }
            }
        });
    }

    if (btnToggleSidebar) {
        btnToggleSidebar.addEventListener("click", () => {
            const collapsed = !document.body.classList.contains("sidebar-collapsed");
            document.body.classList.toggle("sidebar-collapsed", collapsed);
            localStorage.setItem("fg_sidebar_collapsed", collapsed ? "true" : "false");
            
            const toolText = btnToggleSidebar.querySelector(".tool-text");
            if (toolText) {
                toolText.textContent = collapsed ? "Expand" : "Collapse";
            }
            btnToggleSidebar.setAttribute("title", collapsed ? "Expand Sidebar" : "Collapse Sidebar");
        });
    }

    themeButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const darkMode = !document.body.classList.contains("dark-mode");
            document.body.classList.toggle("dark-mode", darkMode);
            localStorage.setItem("fg_theme", darkMode ? "dark" : "light");
            updateThemeButtons(darkMode);
        });
    });

    // Handle Search input filtering
    inputSearch.addEventListener("input", () => renderTopTalkers());
    inputDeviceSearch.addEventListener("input", () => renderDevices());

    // Handle Tab buttons click for Top Talkers
    tabButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            tabButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeTab = e.target.getAttribute("data-tab");
            fetchTopTalkers();
        });
    });

    trafficRangeButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            trafficRangeButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeTrafficRange = e.target.getAttribute("data-range");
            fetchTrafficTimeSeries();
        });
    });

    trafficMetricButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            trafficMetricButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeTrafficMetric = e.target.getAttribute("data-metric");
            renderTrafficChart();
        });
    });

    // Handle triage status filter buttons
    triageFilterButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            triageFilterButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeTriageFilter = e.target.getAttribute("data-status");
            renderAnomalies();
        });
    });

    // Handle Search/Filter for anomalies
    document.getElementById("search-anomalies").addEventListener("input", () => {
        renderAnomalies();
    });
    document.getElementById("filter-anomalies-severity").addEventListener("change", () => {
        renderAnomalies();
    });

    document.getElementById("btn-close-anomaly-details").addEventListener("click", () => {
        selectedAnomalyId = null;
        anomalyDetailsEmpty.classList.remove("hidden");
        anomalyDetailsContent.classList.add("hidden");
        renderAnomalies();
    });

    document.getElementById("btn-close-device-details").addEventListener("click", () => {
        selectedDeviceIP = null;
        detailsEmpty.classList.remove("hidden");
        detailsContent.classList.add("hidden");
        renderDevices();
    });

    // Handle Search/Pagination for audit logs
    document.getElementById("search-audit-logs").addEventListener("input", () => {
        auditLogPage = 0;
        renderAuditLogs();
    });
    document.getElementById("select-audit-limit").addEventListener("change", (e) => {
        auditLogPageSize = parseInt(e.target.value, 10);
        auditLogPage = 0;
        renderAuditLogs();
    });
    document.getElementById("btn-audit-prev").addEventListener("click", () => {
        if (auditLogPage > 0) {
            auditLogPage--;
            renderAuditLogs();
        }
    });
    document.getElementById("btn-audit-next").addEventListener("click", () => {
        auditLogPage++;
        renderAuditLogs();
    });

    // Webhook custom headers dynamic list editor
    document.getElementById("btn-add-webhook-header").addEventListener("click", () => {
        appendWebhookHeaderRow("", "");
    });

    let settingsData = null;
    let activeSettingsSection = "access";

    function getSettingsSectionLabel(sec) {
        const labels = {
            access: "Access Control",
            network: "Network Settings",
            collectors: "Collectors Setup",
            storage: "Storage & Retention",
            thresholds: "Detection Thresholds",
            notifications: "Notifications & Routing",
            system: "System Settings"
        };
        return labels[sec] || sec;
    }

    function updateSettingsNavActive(sec) {
        document.querySelectorAll(".settings-nav .settings-nav-link").forEach(link => {
            if (link.getAttribute("data-section") === sec) {
                link.classList.add("active");
            } else {
                link.classList.remove("active");
            }
        });
    }

    function switchSettingsSection(section) {
        if (unsavedChanges[activeSettingsSection]) {
            if (!confirm(`You have unsaved changes in the ${getSettingsSectionLabel(activeSettingsSection)} section. Do you want to discard them?`)) {
                updateSettingsNavActive(activeSettingsSection);
                return;
            }
            markUnsaved(activeSettingsSection, false);
        }

        activeSettingsSection = section;

        document.querySelectorAll(".settings-main .settings-card").forEach(card => {
            const id = card.getAttribute("id");
            if (id === `settings-${section}`) {
                card.classList.remove("hidden");
            } else {
                card.classList.add("hidden");
            }
        });

        updateSettingsNavActive(section);
    }

    function markUnsaved(section, isUnsaved) {
        unsavedChanges[section] = isUnsaved;
        const card = document.getElementById(`settings-${section}`);
        if (!card) return;
        
        let badge = card.querySelector(".unsaved-badge");
        if (isUnsaved) {
            if (!badge) {
                badge = document.createElement("span");
                badge.className = "badge badge-warning unsaved-badge";
                badge.style.marginLeft = "0.5rem";
                badge.style.fontSize = "0.7rem";
                badge.style.background = "#fb923c";
                badge.style.color = "#fff";
                badge.style.borderRadius = "4px";
                badge.style.padding = "0.1rem 0.3rem";
                badge.textContent = "Unsaved Changes";
                const h3 = card.querySelector(".settings-card-header h3");
                if (h3) h3.appendChild(badge);
            }
            const navLink = document.querySelector(`.settings-nav a[data-section="${section}"]`);
            if (navLink && !navLink.querySelector(".unsaved-dot")) {
                const dot = document.createElement("span");
                dot.className = "unsaved-dot";
                dot.style.display = "inline-block";
                dot.style.width = "6px";
                dot.style.height = "6px";
                dot.style.background = "#fb923c";
                dot.style.borderRadius = "50%";
                dot.style.marginLeft = "0.5rem";
                navLink.appendChild(dot);
            }
        } else {
            if (badge) badge.remove();
            const navLink = document.querySelector(`.settings-nav a[data-section="${section}"]`);
            if (navLink) {
                const dot = navLink.querySelector(".unsaved-dot");
                if (dot) dot.remove();
            }
        }
    }

    async function fetchSettings() {
        try {
            const resp = await fetch("/api/settings");
            if (resp.status === 401) {
                showAuthOverlay("login", "Session expired. Sign in again.");
                return;
            }
            if (!resp.ok) throw new Error("Settings fetch failed");
            settingsData = await resp.json();
            
            // Check first run status
            if (!settingsData.first_run_completed) {
                viewWizard.classList.remove("hidden");
                if (autoRefreshTimer) {
                    clearInterval(autoRefreshTimer);
                    autoRefreshTimer = null;
                }
            } else {
                viewWizard.classList.add("hidden");
            }

            // Populate settings inputs
            document.getElementById("setting-access-password").value = "";
            document.getElementById("setting-access-confirm").value = "";
            document.getElementById("setting-port").value = settingsData.port || "8080";
            document.getElementById("setting-subnets").value = settingsData.local_subnets.join(", ");
            document.getElementById("setting-netflow").value = settingsData.netflow_port;
            document.getElementById("setting-sflow").value = settingsData.sflow_port;
            document.getElementById("setting-suricata-path").value = settingsData.suricata_eve_path || "";
            document.getElementById("setting-storage-dir").value = settingsData.storage_dir || "/data";
            document.getElementById("setting-backend").value = settingsData.storage_backend;
            document.getElementById("setting-retention").value = settingsData.retention_days || 7;
            document.getElementById("setting-threshold-pps").value = settingsData.ddos_threshold_pps || 5000;
            document.getElementById("setting-threshold-bps").value = settingsData.ddos_threshold_bps || 10000000;
            document.getElementById("setting-threshold-syn").value = settingsData.syn_flood_threshold_pps || 1000;
            document.getElementById("setting-threshold-udp").value = settingsData.udp_flood_threshold_pps || 3000;
            document.getElementById("setting-threshold-icmp").value = settingsData.icmp_flood_threshold_pps || 500;
            document.getElementById("setting-webhook-url").value = settingsData.webhook_url;
            document.getElementById("setting-webhook-format").value = settingsData.webhook_format;
            document.getElementById("setting-telegram-enabled").checked = settingsData.telegram_enabled;
            document.getElementById("setting-telegram-token").value = settingsData.telegram_token || "";
            document.getElementById("setting-telegram-chat-id").value = settingsData.telegram_chat_id || "";
            document.getElementById("setting-loglevel").value = settingsData.log_level || "info";
            document.getElementById("setting-env").value = settingsData.environment || "production";
            renderWebhookHeaders(settingsData.webhook_headers || {});

            // Clear any unsaved changes badges
            Object.keys(unsavedChanges).forEach(k => markUnsaved(k, false));
        } catch (err) {
            console.error("Error fetching settings: ", err);
        }
    }

    async function saveSettings(payload) {
        try {
            const resp = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || "Save settings failed");
            }
            
            let note = "";
            if (settingsData && (
                payload.port !== settingsData.port ||
                payload.netflow_port !== settingsData.netflow_port ||
                payload.sflow_port !== settingsData.sflow_port ||
                payload.storage_dir !== settingsData.storage_dir ||
                payload.storage_backend !== settingsData.storage_backend
            )) {
                note = " (Note: Port, directory, and backend changes require a daemon restart)";
            }
            showToast("Settings saved successfully." + note);
            await fetchSettings();
        } catch (err) {
            showToast("Settings save failed: " + err.message, "error");
            throw err;
        }
    }

    // Settings Access Form Submit
    document.getElementById("form-settings-access").addEventListener("submit", (e) => {
        e.preventDefault();
        if (!settingsData) return;
        const password = document.getElementById("setting-access-password").value;
        const confirm = document.getElementById("setting-access-confirm").value;
        if (password !== confirm) {
            showToast("Passwords do not match", "error");
            return;
        }
        if (password.length > 0 && password.length < 10) {
            showToast("Password must be at least 10 characters long", "error");
            return;
        }
        const payload = {
            ...settingsData,
            admin_password: password
        };
        saveSettings(payload).then(() => {
            markUnsaved("access", false);
            document.getElementById("setting-access-password").value = "";
            document.getElementById("setting-access-confirm").value = "";
        }).catch(() => {});
    });

    // Settings Network Form Submit
    document.getElementById("form-settings-network").addEventListener("submit", (e) => {
        e.preventDefault();
        if (!settingsData) return;
        const port = document.getElementById("setting-port").value.trim();
        const subnets = document.getElementById("setting-subnets").value.split(",").map(s => s.trim()).filter(s => s !== "");
        const payload = {
            ...settingsData,
            port: port,
            local_subnets: subnets
        };
        saveSettings(payload).then(() => markUnsaved("network", false)).catch(() => {});
    });

    // Settings Collectors Form Submit
    document.getElementById("form-settings-collectors").addEventListener("submit", (e) => {
        e.preventDefault();
        if (!settingsData) return;
        const netflow = parseInt(document.getElementById("setting-netflow").value, 10);
        const sflow = parseInt(document.getElementById("setting-sflow").value, 10);
        const suricata = document.getElementById("setting-suricata-path").value.trim();
        const payload = {
            ...settingsData,
            netflow_port: netflow,
            sflow_port: sflow,
            suricata_eve_path: suricata
        };
        saveSettings(payload).then(() => markUnsaved("collectors", false)).catch(() => {});
    });

    // Settings Storage Form Submit
    document.getElementById("form-settings-storage").addEventListener("submit", (e) => {
        e.preventDefault();
        if (!settingsData) return;
        const dir = document.getElementById("setting-storage-dir").value.trim();
        const backend = document.getElementById("setting-backend").value;
        const retention = parseInt(document.getElementById("setting-retention").value, 10);
        const payload = {
            ...settingsData,
            storage_dir: dir,
            storage_backend: backend,
            retention_days: retention
        };
        saveSettings(payload).then(() => markUnsaved("storage", false)).catch(() => {});
    });

    // Settings Thresholds Form Submit
    document.getElementById("form-settings-thresholds").addEventListener("submit", (e) => {
        e.preventDefault();
        if (!settingsData) return;
        const pps = parseInt(document.getElementById("setting-threshold-pps").value, 10);
        const bps = parseInt(document.getElementById("setting-threshold-bps").value, 10);
        const syn = parseInt(document.getElementById("setting-threshold-syn").value, 10);
        const udp = parseInt(document.getElementById("setting-threshold-udp").value, 10);
        const icmp = parseInt(document.getElementById("setting-threshold-icmp").value, 10);
        const payload = {
            ...settingsData,
            ddos_threshold_pps: pps,
            ddos_threshold_bps: bps,
            syn_flood_threshold_pps: syn,
            udp_flood_threshold_pps: udp,
            icmp_flood_threshold_pps: icmp
        };
        saveSettings(payload).then(() => markUnsaved("thresholds", false)).catch(() => {});
    });

    // Settings Webhook Form Submit
    document.getElementById("form-settings-webhook").addEventListener("submit", (e) => {
        e.preventDefault();
        if (!settingsData) return;
        const url = document.getElementById("setting-webhook-url").value;
        const format = document.getElementById("setting-webhook-format").value;
        const tgEnabled = document.getElementById("setting-telegram-enabled").checked;
        const tgToken = document.getElementById("setting-telegram-token").value;
        const tgChatId = document.getElementById("setting-telegram-chat-id").value;

        const headerRows = document.querySelectorAll("#webhook-headers-list .webhook-header-row");
        const headers = {};
        headerRows.forEach(row => {
            const key = row.querySelector(".header-key").value.trim();
            const val = row.querySelector(".header-value").value.trim();
            if (key !== "") {
                headers[key] = val;
            }
        });
        
        const payload = {
            ...settingsData,
            webhook_url: url,
            webhook_format: format,
            webhook_headers: headers,
            telegram_enabled: tgEnabled,
            telegram_token: tgToken,
            telegram_chat_id: tgChatId
        };
        saveSettings(payload).then(() => markUnsaved("notifications", false)).catch(() => {});
    });

    // Settings System Form Submit
    document.getElementById("form-settings-system").addEventListener("submit", (e) => {
        e.preventDefault();
        if (!settingsData) return;
        const loglevel = document.getElementById("setting-loglevel").value;
        const env = document.getElementById("setting-env").value;
        const payload = {
            ...settingsData,
            log_level: loglevel,
            environment: env
        };
        saveSettings(payload).then(() => markUnsaved("system", false)).catch(() => {});
    });

    // Bind settings navigation links
    document.querySelectorAll(".settings-nav .settings-nav-link").forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const sec = link.getAttribute("data-section");
            if (sec === "integrations") {
                if (unsavedChanges[activeSettingsSection]) {
                    if (!confirm(`You have unsaved changes in the ${getSettingsSectionLabel(activeSettingsSection)} section. Do you want to discard them?`)) {
                        return;
                    }
                    markUnsaved(activeSettingsSection, false);
                }
                activeSettingsSection = sec;
                document.querySelectorAll(".settings-main .settings-card").forEach(c => {
                    if (c.getAttribute("id") === "settings-integrations") {
                        c.classList.remove("hidden");
                    } else {
                        c.classList.add("hidden");
                    }
                });
                updateSettingsNavActive(sec);
            } else {
                switchSettingsSection(sec);
            }
        });
    });

    // Setup input change event listeners
    const formsToTrack = [
        { id: "form-settings-access", name: "access" },
        { id: "form-settings-network", name: "network" },
        { id: "form-settings-collectors", name: "collectors" },
        { id: "form-settings-storage", name: "storage" },
        { id: "form-settings-thresholds", name: "thresholds" },
        { id: "form-settings-webhook", name: "notifications" },
        { id: "form-settings-system", name: "system" }
    ];
    formsToTrack.forEach(sec => {
        const form = document.getElementById(sec.id);
        if (form) {
            form.querySelectorAll("input, select, textarea").forEach(input => {
                input.addEventListener("input", () => markUnsaved(sec.name, true));
                input.addEventListener("change", () => markUnsaved(sec.name, true));
            });
        }
    });

    const btnAddWebhookHeader = document.getElementById("btn-add-webhook-header");
    if (btnAddWebhookHeader) {
        btnAddWebhookHeader.addEventListener("click", () => markUnsaved("notifications", true));
    }

    // Settings Test Alert Click
    document.getElementById("btn-test-alert").addEventListener("click", async () => {
        try {
            const resp = await fetch("/api/settings/test-alert", {
                method: "POST"
            });
            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || "Failed to trigger test alert");
            }
            showToast("Test alert sent.");
        } catch (err) {
            showToast("Test alert failed: " + err.message, "error");
        }
    });

    // Policies Section Event Listeners
    if (btnAddPolicy) {
        btnAddPolicy.addEventListener("click", startAddPolicy);
    }
    if (btnCancelPolicy) {
        btnCancelPolicy.addEventListener("click", resetPolicyDetails);
    }
    const btnDeletePolicy = document.getElementById("btn-delete-policy");
    if (btnDeletePolicy) {
        btnDeletePolicy.addEventListener("click", deletePolicyClick);
    }
    if (btnClosePolicyDetails) {
        btnClosePolicyDetails.addEventListener("click", () => {
            resetPolicyDetails();
            renderPolicies();
        });
    }
    if (selectPolicyScope) {
        selectPolicyScope.addEventListener("change", () => {
            updateTargetFieldLabel();
            updatePrecedencePreview();
        });
    }
    if (formPolicyEditor) {
        formPolicyEditor.addEventListener("submit", savePolicySubmit);
    }
    const formPolicyInputs = [
        inputPolicyName,
        inputPolicyTarget,
        selectPolicySeverityThreshold,
        selectPolicyCooldown,
        inputPolicyQuietHoursStart,
        inputPolicyQuietHoursEnd,
        inputPolicySuppressed
    ];
    formPolicyInputs.forEach(input => {
        if (input) {
            input.addEventListener("input", updatePrecedencePreview);
            input.addEventListener("change", updatePrecedencePreview);
        }
    });
    document.querySelectorAll(".policy-channel-checkbox").forEach(cb => {
        cb.addEventListener("change", updatePrecedencePreview);
    });

    // Notifications Section Event Listeners
    if (btnAddNotificationRule) {
        btnAddNotificationRule.addEventListener("click", startAddNotificationRule);
    }
    if (btnDeleteNotificationRule) {
        btnDeleteNotificationRule.addEventListener("click", deleteNotificationRuleClick);
    }
    if (btnTestNotificationRule) {
        btnTestNotificationRule.addEventListener("click", testNotificationRuleClick);
    }
    if (btnCloseNotificationDetails) {
        btnCloseNotificationDetails.addEventListener("click", () => {
            resetNotificationRuleDetails();
            renderNotificationRules();
        });
    }
    if (selectNotificationRuleScope) {
        selectNotificationRuleScope.addEventListener("change", () => {
            updateNotificationTargetFieldVisibility();
            updateNotificationRulePreview();
        });
    }
    if (formNotificationEditor) {
        formNotificationEditor.addEventListener("submit", saveNotificationRuleSubmit);
    }
    if (selectNotificationLogsLimit) {
        selectNotificationLogsLimit.addEventListener("change", fetchNotificationLogs);
    }

    const formNotificationInputs = [
        inputNotificationRuleName,
        inputNotificationRuleEnabled,
        selectNotificationRuleSeverity,
        inputNotificationRuleAlertTypes,
        inputNotificationRuleTarget,
        inputNotificationRuleCooldown
    ];
    formNotificationInputs.forEach(input => {
        if (input) {
            input.addEventListener("input", updateNotificationRulePreview);
            input.addEventListener("change", updateNotificationRulePreview);
        }
    });
    document.querySelectorAll(".rule-channel-checkbox").forEach(cb => {
        cb.addEventListener("change", updateNotificationRulePreview);
    });

    // Wizard Setup Form Submit
    document.getElementById("form-wizard").addEventListener("submit", async (e) => {
        e.preventDefault();
        const subnets = document.getElementById("wizard-subnets").value.split(",").map(s => s.trim()).filter(s => s !== "");
        const netflow = parseInt(document.getElementById("wizard-netflow").value, 10);
        const sflow = parseInt(document.getElementById("wizard-sflow").value, 10);
        const backend = document.getElementById("wizard-backend").value;
        
        const payload = {
            port: "8080",
            netflow_port: netflow,
            sflow_port: sflow,
            storage_dir: "/data",
            log_level: "info",
            environment: "production",
            local_subnets: subnets,
            storage_backend: backend,
            first_run_completed: true
        };
        
        try {
            const resp = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || "Setup failed");
            }
            showToast("Setup saved.");
            viewWizard.classList.add("hidden");
            
            settingsData = await resp.json();
            autoRefreshTimer = setInterval(loadData, 5000);
            switchView("dashboard");
        } catch (err) {
            showToast("Setup failed: " + err.message, "error");
        }
    });

    // Initial Load
    async function init() {
        applyStoredShellPreferences();
        const auth = await fetchAuthStatus();
        if (auth.setup_required) {
            showAuthOverlay("setup", "Use at least 10 characters.");
            return;
        }
        if (!auth.authenticated) {
            showAuthOverlay("login");
            return;
        }
        await initAuthenticatedApp();
    }

    async function initAuthenticatedApp() {
        await fetchSettings();
        if (settingsData && settingsData.first_run_completed) {
            const route = parseHashRoute();
            switchView(route.viewName, route.ip);
            autoRefreshTimer = setInterval(loadData, 5000);
        }
    }
    init();

    // Custom Webhook Headers UI Helpers
    function renderWebhookHeaders(headers) {
        const listContainer = document.getElementById("webhook-headers-list");
        if (!listContainer) return;
        listContainer.innerHTML = "";

        Object.entries(headers).forEach(([key, val]) => {
            appendWebhookHeaderRow(key, val);
        });
    }

    function appendWebhookHeaderRow(key = "", val = "") {
        const listContainer = document.getElementById("webhook-headers-list");
        if (!listContainer) return;

        const row = document.createElement("div");
        row.className = "webhook-header-row";
        row.style.display = "flex";
        row.style.gap = "0.5rem";
        row.style.alignItems = "center";

        const keyInput = document.createElement("input");
        keyInput.type = "text";
        keyInput.placeholder = "Header Key";
        keyInput.className = "form-control header-key";
        keyInput.value = key;
        keyInput.style.cssText = "flex: 1; height: 32px; font-size: 0.8rem; padding: 0 0.5rem;";

        const valueInput = document.createElement("input");
        valueInput.type = "text";
        valueInput.placeholder = "Value";
        valueInput.className = "form-control header-value";
        valueInput.value = val;
        valueInput.style.cssText = "flex: 2; height: 32px; font-size: 0.8rem; padding: 0 0.5rem;";

        const removeButton = document.createElement("button");
        removeButton.type = "button";
        removeButton.className = "btn-secondary btn-remove-header";
        removeButton.textContent = "x";
        removeButton.style.cssText = "height: 32px; width: 32px; padding: 0; line-height: 30px; font-size: 1.1rem; text-align: center; border-radius: 6px; cursor: pointer; flex-shrink: 0;";
        removeButton.addEventListener("click", () => {
            row.remove();
        });

        row.append(keyInput, valueInput, removeButton);
        listContainer.appendChild(row);
    }
});
