import { state } from './state.js';
import * as api from './api.js';
import { Router } from './router.js';
import { renderTrafficView, bindTrafficEvents } from './views/traffic.js';
import { renderDevicesView, bindDevicesEvents } from './views/devices.js';
import { renderAlertsView, bindAlertsEvents } from './views/alerts.js';
import { renderPoliciesView, bindPoliciesEvents } from './views/policies.js';
import { renderNotificationsView, bindNotificationsEvents } from './views/notifications.js';
import { renderAuditView, bindAuditEvents } from './views/audit.js';
import { renderSettingsView, bindSettingsEvents } from './views/settings.js';

let authMode = "login";

// Global toast notifier helper
window.showToast = function(message, type = "success") {
    const toastContainer = document.getElementById("toast-container");
    if (!toastContainer) return;
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;
    toastContainer.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 3000);
};

window.showAuthOverlay = function(mode, message = "") {
    authMode = mode;
    const authOverlay = document.getElementById("auth-overlay");
    const authTitle = document.getElementById("auth-title");
    const authSubtitle = document.getElementById("auth-subtitle");
    const btnAuthSubmit = document.getElementById("btn-auth-submit");
    const authPassword = document.getElementById("auth-password");
    const authMessage = document.getElementById("auth-message");

    if (!authOverlay) return;
    if (authTitle) authTitle.textContent = mode === "setup" ? "Set Admin Password" : "FlowGuard Lite";
    if (authSubtitle) {
        authSubtitle.textContent = mode === "setup"
            ? "Create the local admin password for this FlowGuard node"
            : "Sign in to this FlowGuard node";
    }
    if (btnAuthSubmit) btnAuthSubmit.textContent = mode === "setup" ? "Create Password" : "Sign In";
    if (authPassword) {
        authPassword.value = "";
        authPassword.autocomplete = mode === "setup" ? "new-password" : "current-password";
        authOverlay.classList.remove("hidden");
        authPassword.focus();
    }
    if (authMessage) authMessage.textContent = message;
};

function hideAuthOverlay() {
    const authOverlay = document.getElementById("auth-overlay");
    if (authOverlay) authOverlay.classList.add("hidden");
}

async function loadData(isManualRefresh = false) {
    const btnRefresh = document.getElementById("btn-refresh");
    const refreshIcon = btnRefresh ? btnRefresh.querySelector("svg") : null;
    if (btnRefresh) {
        btnRefresh.disabled = true;
        if (refreshIcon) refreshIcon.classList.add("icon-spin");
    }

    try {
        // Fetch health & risk status
        const [health, threatRisk] = await Promise.all([
            api.fetchHealth(),
            api.fetchThreatRisk()
        ]).catch(err => {
            console.error("Health/Risk check failed: ", err);
            return [{}, []];
        });

        // Set status indicator
        const statusIndicator = document.querySelector(".status-indicator");
        const statusLabel = document.querySelector(".status-label");
        if (statusIndicator && statusLabel) {
            statusIndicator.className = "status-indicator";
            if (health.healthy) {
                statusIndicator.classList.add("healthy");
                statusLabel.textContent = "System Healthy";
            } else {
                statusIndicator.classList.add("warning");
                statusLabel.textContent = health.error_message || "Collector Error";
            }
        }

        // Set state risk devices
        state.riskDevicesData = threatRisk || [];

        // View-specific data fetching
        if (state.activeView === "dashboard") {
            const range = trafficRangeConfig();
            const [exporters, topTalkers, devices, anomalies, trafficSeries] = await Promise.all([
                api.fetchExporters(),
                api.fetchTopTalkers(state.activeTab, range),
                api.fetchDevices(),
                api.fetchAnomalies(),
                api.fetchTrafficTimeSeries(range)
            ]).catch(err => {
                console.error("Dashboard data load failed: ", err);
                return [[], [], [], [], []];
            });

            state.exportersData = exporters || [];
            state.talkersData = topTalkers || [];
            state.devicesData = devices || [];
            state.anomaliesData = anomalies || [];
            state.trafficSeriesData = trafficSeries || [];

            renderTrafficView();
        } else if (state.activeView === "devices") {
            state.devicesData = await api.fetchDevices().catch(() => []);
            renderDevicesView();
        } else if (state.activeView === "anomalies") {
            state.anomaliesData = await api.fetchAnomalies().catch(() => []);
            renderAlertsView();
        } else if (state.activeView === "policies") {
            state.policiesData = await api.fetchPolicies().catch(() => []);
            renderPoliciesView();
        } else if (state.activeView === "notifications") {
            const [rules, logs] = await Promise.all([
                api.fetchNotificationRules(),
                api.fetchNotificationLogs()
            ]).catch(() => [[], []]);
            state.notificationRulesData = rules;
            state.notificationLogsData = logs;
            renderNotificationsView();
        } else if (state.activeView === "audit") {
            state.auditLogsData = await api.fetchAuditLogs().catch(() => []);
            renderAuditView();
        } else if (state.activeView === "settings") {
            // Settings are configuration data, not live telemetry.
            // Only load once when first entering the view (triggered by the router),
            // or explicitly via the manual refresh button. Never auto-refresh,
            // because it would clobber in-progress form edits.
            if (!state.settingsData || isManualRefresh) {
                state.settingsData = await api.fetchSettings().catch(() => null);
                renderSettingsView();
            }
        }
    } finally {
        if (btnRefresh) {
            btnRefresh.disabled = false;
            if (refreshIcon) refreshIcon.classList.remove("icon-spin");
        }
    }
}

// Help resolve circular imports for trafficRangeConfig
function trafficRangeConfig() {
    const end = new Date();
    const configs = {
        "1h": { start: new Date(end.getTime() - 60 * 60 * 1000), bucket: 60 },
        "6h": { start: new Date(end.getTime() - 6 * 60 * 60 * 1000), bucket: 300 },
        "24h": { start: new Date(end.getTime() - 24 * 60 * 60 * 1000), bucket: 900 },
        "7d": { start: new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000), bucket: 3600 }
    };
    return { ...configs[state.activeTrafficRange], end };
}

// Shell view titles updates on route change
window.addEventListener("viewchange", (e) => {
    const { viewName } = e.detail;
    const workspaceTitle = document.getElementById("workspace-title");
    const workspaceSubtitle = document.querySelector(".workspace-subtitle");

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

    // When leaving settings, clear cached data so next visit always fetches fresh config.
    // When entering settings via navigation, treat it as a manual (forced) load.
    const isEnteringSettings = viewName === "settings";
    if (!isEnteringSettings && state.settingsData) {
        state.settingsData = null;
    }

    loadData(isEnteringSettings);
});

function applyStoredShellPreferences() {
    const sidebarCollapsed = localStorage.getItem("fg_sidebar_collapsed") === "true";
    const darkMode = localStorage.getItem("fg_theme") === "dark";

    document.body.classList.toggle("sidebar-collapsed", sidebarCollapsed);
    document.body.classList.toggle("dark-mode", darkMode);

    const btnToggleSidebar = document.getElementById("btn-toggle-sidebar");
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
    const themeButtons = document.querySelectorAll(".theme-toggle-btn");
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

async function initAuthenticatedApp() {
    state.settingsData = await api.fetchSettings().catch(() => null);
    const viewWizard = document.getElementById("view-wizard");
    if (state.settingsData && !state.settingsData.first_run_completed) {
        if (viewWizard) viewWizard.classList.remove("hidden");
        if (window.autoRefreshTimer) {
            clearInterval(window.autoRefreshTimer);
            window.autoRefreshTimer = null;
        }
        return;
    }
    if (viewWizard) viewWizard.classList.add("hidden");

    if (state.settingsData && state.settingsData.first_run_completed) {
        // Setup router
        const routes = {
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
        const router = new Router(routes, "dashboard");
        router.init();

        window.autoRefreshTimer = setInterval(loadData, 5000);
    }
}

// DOMContentLoaded bootstrapping
document.addEventListener("DOMContentLoaded", async () => {
    applyStoredShellPreferences();

    // Bind sidebar minimize click
    const btnToggleSidebar = document.getElementById("btn-toggle-sidebar");
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

    // Bind theme button toggle click
    const themeButtons = document.querySelectorAll(".theme-toggle-btn");
    themeButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const darkMode = !document.body.classList.contains("dark-mode");
            document.body.classList.toggle("dark-mode", darkMode);
            localStorage.setItem("fg_theme", darkMode ? "dark" : "light");
            updateThemeButtons(darkMode);
        });
    });

    // Bind navigation buttons hash triggers
    const navDashboard = document.getElementById("nav-dashboard");
    const navDevices = document.getElementById("nav-devices");
    const navAnomalies = document.getElementById("nav-anomalies");
    const navPolicies = document.getElementById("nav-policies");
    const navNotifications = document.getElementById("nav-notifications");
    const navAudit = document.getElementById("nav-audit");
    const navSettings = document.getElementById("nav-settings");

    if (navDashboard) navDashboard.addEventListener("click", () => { window.location.hash = "#/traffic"; });
    if (navDevices) navDevices.addEventListener("click", () => { window.location.hash = "#/devices"; });
    if (navAnomalies) navAnomalies.addEventListener("click", () => { window.location.hash = "#/alerts"; });
    if (navPolicies) navPolicies.addEventListener("click", () => { window.location.hash = "#/policies"; });
    if (navNotifications) navNotifications.addEventListener("click", () => { window.location.hash = "#/notifications"; });
    if (navAudit) navAudit.addEventListener("click", () => { window.location.hash = "#/audit"; });
    if (navSettings) navSettings.addEventListener("click", () => { window.location.hash = "#/settings"; });

    // Bind manual refresh trigger
    const btnRefresh = document.getElementById("btn-refresh");
    if (btnRefresh) {
        btnRefresh.addEventListener("click", () => {
            loadData(true);
        });
    }

    // Bind Collector health accordion collapse
    const headerCollectorHealth = document.getElementById("header-collector-health");
    const bodyCollectorHealth = document.getElementById("body-collector-health");
    const iconCollectorHealth = document.getElementById("icon-collector-health");
    if (headerCollectorHealth && bodyCollectorHealth && iconCollectorHealth) {
        headerCollectorHealth.addEventListener("click", () => {
            const isHidden = bodyCollectorHealth.style.display === "none";
            bodyCollectorHealth.style.display = isHidden ? "block" : "none";
            iconCollectorHealth.style.transform = isHidden ? "rotate(180deg)" : "rotate(0deg)";
        });
    }

    // Bind auth form submit
    const formAuth = document.getElementById("form-auth");
    const authPassword = document.getElementById("auth-password");
    const authMessage = document.getElementById("auth-message");
    if (formAuth) {
        formAuth.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!authPassword) return;
            const password = authPassword.value;
            try {
                if (authMessage) authMessage.textContent = "";
                if (authMode === "setup") {
                    await api.submitSetup(password);
                } else {
                    await api.submitLogin(password);
                }
                hideAuthOverlay();
                await initAuthenticatedApp();
            } catch (err) {
                if (authMessage) authMessage.textContent = err.message;
            }
        });
    }

    // Bind logout button click
    const btnLogout = document.getElementById("btn-logout");
    if (btnLogout) {
        btnLogout.addEventListener("click", async () => {
            try {
                await api.submitLogout();
            } finally {
                if (window.autoRefreshTimer) {
                    clearInterval(window.autoRefreshTimer);
                    window.autoRefreshTimer = null;
                }
                window.showAuthOverlay("login", "Signed out.");
            }
        });
    }

    // Bind wizard save setup form submit
    const formWizard = document.getElementById("form-wizard");
    if (formWizard) {
        formWizard.addEventListener("submit", async (e) => {
            e.preventDefault();
            const subnetsVal = document.getElementById("wizard-subnets").value.trim();
            const backend = document.getElementById("wizard-backend").value;
            const subnets = subnetsVal.split(",").map(s => s.trim()).filter(s => s !== "");
            
            const netflowVal = parseInt(document.getElementById("wizard-netflow").value, 10) || 2055;
            const sflowVal = parseInt(document.getElementById("wizard-sflow").value, 10) || 6343;
            
            const payload = {
                port: "8080",
                netflow_port: netflowVal,
                sflow_port: sflowVal,
                storage_dir: "/data",
                log_level: "info",
                environment: "production",
                local_subnets: subnets,
                storage_backend: backend,
                first_run_completed: true,
                retention_days: 7,
                ddos_threshold_pps: 5000,
                ddos_threshold_bps: 10485760,
                syn_flood_threshold_pps: 1000,
                udp_flood_threshold_pps: 3000,
                icmp_flood_threshold_pps: 500
            };
            
            try {
                await api.saveSettings("setup", payload);
                window.showToast("Setup saved.");
                const viewWizard = document.getElementById("view-wizard");
                if (viewWizard) viewWizard.classList.add("hidden");
                
                await initAuthenticatedApp();
                window.location.hash = "#/traffic";
            } catch (err) {
                window.showToast("Setup failed: " + err.message, "error");
            }
        });
    }

    // Bind pagination audit logs size select change
    const selectAuditLimit = document.getElementById("select-audit-limit");
    if (selectAuditLimit) {
        selectAuditLimit.addEventListener("change", (e) => {
            state.auditLogPageSize = parseInt(e.target.value, 10);
            state.auditLogPage = 0;
            renderAuditView();
        });
    }

    // Bind View-specific event controls
    bindTrafficEvents(loadData);
    bindDevicesEvents();
    bindAlertsEvents();
    bindPoliciesEvents(loadData);
    bindNotificationsEvents(loadData);
    bindAuditEvents();
    bindSettingsEvents(loadData);

    // Initial auth status fetch
    try {
        const auth = await fetch("/api/auth/status").then(r => r.json());
        if (auth.setup_required) {
            window.showAuthOverlay("setup", "Use at least 10 characters.");
            return;
        }
        if (!auth.authenticated) {
            window.showAuthOverlay("login");
            return;
        }
        await initAuthenticatedApp();
    } catch (err) {
        console.error("Initial auth check failed:", err);
    }
});
