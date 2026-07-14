import { state, hasUnsavedChanges } from './state.js';
import * as api from '../lib/api.js';
import { Router } from '../routes/router.js';
import { bindOverviewEvents } from '../features/overview/overviewView.js';
import { bindTrafficEvents } from '../features/traffic/trafficView.js';
import { bindDevicesEvents } from '../features/devices/devicesView.js';
import { bindAlertsEvents } from '../features/alerts/alertsView.js';
import { bindPoliciesEvents } from '../features/policies/policiesView.js';
import { bindPolicyModalEvents } from '../features/policies/policyModal.js';
import { bindNotificationsEvents } from '../features/notifications/notificationsView.js';
import { renderAuditView, bindAuditEvents } from '../features/audit/auditView.js';
import { renderSettingsView, bindSettingsEvents } from '../features/settings/settingsView.js';
import { loadData } from '../loaders/viewDataLoader.js';
import { scheduleAutoRefresh, stopAutoRefresh } from './autoRefresh.js';
import { routes, viewTitles } from './viewRegistry.js';
import { bindGlobalRangeButtons, syncGlobalRangeButtons, syncGlobalRangeVisibility } from '../services/globalRangeControls.js';
import { currentAuthMode, hideAuthOverlay, installAuthOverlayGlobal, showAuthOverlay } from '../services/authOverlay.js';

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


// Shell view titles updates on route change
window.addEventListener("viewchange", (e) => {
    const { viewName, param } = e.detail;
    const previousView = state.lastRoutedView;
    const workspaceTitle = document.getElementById("workspace-title");
    const workspaceSubtitle = document.querySelector(".workspace-subtitle");

    const title = viewTitles[viewName] || viewTitles.dashboard;
    if (workspaceTitle) workspaceTitle.textContent = title[0];
    if (workspaceSubtitle) workspaceSubtitle.textContent = title[1];
    if (viewName === "settings") {
        state.activeSettingsSection = param || "access";
    }
    syncGlobalRangeButtons(loadData);
    syncGlobalRangeVisibility(viewName);
    scheduleAutoRefresh(viewName, loadData);

    // When leaving settings, clear cached data so next visit always fetches fresh config.
    // When entering settings via navigation, treat it as a manual (forced) load.
    const isEnteringSettings = viewName === "settings";
    if (!isEnteringSettings && state.settingsData) {
        state.settingsData = null;
    }

    state.lastRoutedView = viewName;
    if (isEnteringSettings && previousView === "settings") {
        renderSettingsView();
        return;
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
        btnToggleSidebar.setAttribute("aria-label", sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar");
        btnToggleSidebar.setAttribute("aria-expanded", sidebarCollapsed ? "false" : "true");
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
        btn.setAttribute("aria-label", darkMode ? "Switch to light mode" : "Switch to dark mode");
        btn.setAttribute("aria-pressed", darkMode ? "true" : "false");
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
        stopAutoRefresh();
        return;
    }
    if (viewWizard) viewWizard.classList.add("hidden");

    if (state.settingsData && state.settingsData.first_run_completed) {
        const router = new Router(routes, "overview");
        router.init();
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
            btnToggleSidebar.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
            btnToggleSidebar.setAttribute("aria-expanded", collapsed ? "false" : "true");
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
    const navOverview = document.getElementById("nav-overview");
    const navDashboard = document.getElementById("nav-dashboard");
    const navDevices = document.getElementById("nav-devices");
    const navAnomalies = document.getElementById("nav-anomalies");
    const navPolicies = document.getElementById("nav-policies");
    const navNotifications = document.getElementById("nav-notifications");
    const navAudit = document.getElementById("nav-audit");
    const navSettings = document.getElementById("nav-settings");

    if (navOverview) navOverview.addEventListener("click", () => { window.location.hash = "#/overview"; });
    if (navDashboard) navDashboard.addEventListener("click", () => { window.location.hash = "#/traffic"; });
    if (navDevices) navDevices.addEventListener("click", () => { window.location.hash = "#/devices"; });
    if (navAnomalies) navAnomalies.addEventListener("click", () => { window.location.hash = "#/alerts"; });
    if (navPolicies) navPolicies.addEventListener("click", () => { window.location.hash = "#/policies"; });
    if (navNotifications) navNotifications.addEventListener("click", () => { window.location.hash = "#/notifications"; });
    if (navAudit) navAudit.addEventListener("click", () => { window.location.hash = "#/audit"; });
    if (navSettings) navSettings.addEventListener("click", () => { window.location.hash = "#/settings/access"; });

    bindGlobalRangeButtons(loadData);

    const selectAutoRefresh = document.getElementById("select-auto-refresh");
    if (selectAutoRefresh) {
        selectAutoRefresh.value = String(state.autoRefreshSeconds);
        selectAutoRefresh.addEventListener("change", (e) => {
            state.autoRefreshSeconds = Number(e.target.value || 0);
            scheduleAutoRefresh(state.activeView, loadData);
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
                if (currentAuthMode() === "setup") {
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
                stopAutoRefresh();
                showAuthOverlay("login", "Signed out.");
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
                unifi_syslog_enabled: false,
                unifi_syslog_port: 5514,
                unifi_syslog_allowed_ips: [],
                storage_dir: "/data",
                log_level: "info",
                environment: "production",
                local_subnets: subnets,
                storage_backend: backend,
                first_run_completed: true,
                retention_days: 7,
                ddos_threshold_pps: 5000,
                ddos_threshold_bps: 10485760,
                ddos_threshold_fps: 1000,
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
                window.location.hash = "#/overview";
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
    bindOverviewEvents(loadData);
    bindTrafficEvents(loadData);
    bindDevicesEvents();
    bindAlertsEvents();
    bindPoliciesEvents(loadData);
    bindPolicyModalEvents();
    bindNotificationsEvents(loadData);
    bindAuditEvents();
    bindSettingsEvents(loadData);

    // Initial auth status fetch
    try {
        installAuthOverlayGlobal();
        const auth = await api.fetchAuthStatus();
        if (auth.setup_required) {
            showAuthOverlay("setup", "Use at least 10 characters.");
            return;
        }
        if (!auth.authenticated) {
            showAuthOverlay("login");
            return;
        }
        await initAuthenticatedApp();
    } catch (err) {
        console.error("Initial auth check failed:", err);
    }

    // Bind window unload intercept for unsaved changes warning
    window.addEventListener("beforeunload", (e) => {
        if (hasUnsavedChanges()) {
            e.preventDefault();
            e.returnValue = "You have unsaved changes. Discard them?";
            return e.returnValue;
        }
    });
});
