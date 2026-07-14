import { state } from '../../app/state.js';
import { renderErrorState } from '../../components/ui/states.js';
import { markUnsaved, syncActiveSettingsSectionFromState, switchSettingsSection } from './settingsSections.js';
import { renderWebhookHeaders, syncNotificationFields, updateTelegramUrlPreview } from './settingsNotifications.js';

export function renderSettingsView() {
    if (state.settingsError) {
        const activeSettingsSection = syncActiveSettingsSectionFromState();
        const sectionEl = document.querySelector(`.settings-section[data-section="${activeSettingsSection}"]`);
        if (sectionEl) {
            sectionEl.innerHTML = renderErrorState(`Failed to load settings: ${state.settingsError}`);
        }
        return;
    }
    if (!state.settingsData) return;
    const activeSettingsSection = syncActiveSettingsSectionFromState();

    const viewWizard = document.getElementById("view-wizard");
    if (viewWizard) {
        if (!state.settingsData.first_run_completed) {
            viewWizard.classList.remove("hidden");
            if (window.autoRefreshTimer) {
                clearInterval(window.autoRefreshTimer);
                window.autoRefreshTimer = null;
            }
        } else {
            viewWizard.classList.add("hidden");
        }
    }

    const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.value = val;
    };
    const setChecked = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.checked = Boolean(val);
    };

    // Helper: only populate a section if the user hasn't made unsaved changes to it.
    // This prevents the 5-second auto-refresh from clobbering in-progress edits.
    const noUnsaved = (section) => !state.unsavedChanges[section];

    // Access (password fields always cleared for security)
    setVal("setting-access-password", "");
    setVal("setting-access-confirm", "");

    if (noUnsaved("network")) {
        setVal("setting-port", state.settingsData.port || "8080");
        setVal("setting-subnets", (state.settingsData.local_subnets || []).join(", "));
    }

    if (noUnsaved("collectors")) {
        setVal("setting-netflow", state.settingsData.netflow_port);
        setVal("setting-sflow", state.settingsData.sflow_port);
        setChecked("setting-unifi-syslog-enabled", state.settingsData.unifi_syslog_enabled);
        setVal("setting-unifi-syslog-port", state.settingsData.unifi_syslog_port || 5514);
        setVal("setting-unifi-syslog-allowed", (state.settingsData.unifi_syslog_allowed_ips || []).join(", "));
        setVal("setting-suricata-path", state.settingsData.suricata_eve_path || "");
        setVal("setting-capture-interface", state.settingsData.capture_interface || "");
        setVal("setting-capture-bpf-filter", state.settingsData.capture_bpf_filter || "ip or ip6");
        setChecked("setting-capture-promiscuous", state.settingsData.capture_promiscuous);
    }

    if (noUnsaved("storage")) {
        setVal("setting-storage-dir", state.settingsData.storage_dir || "/data");
        setVal("setting-backend", state.settingsData.storage_backend);
        setVal("setting-retention", state.settingsData.retention_days || 7);
    }

    if (noUnsaved("thresholds")) {
        setVal("setting-threshold-pps", state.settingsData.ddos_threshold_pps || 5000);
        setVal("setting-threshold-bps", state.settingsData.ddos_threshold_bps || 10000000);
        setVal("setting-threshold-fps", state.settingsData.ddos_threshold_fps || 1000);
        setVal("setting-threshold-syn", state.settingsData.syn_flood_threshold_pps || 1000);
        setVal("setting-threshold-udp", state.settingsData.udp_flood_threshold_pps || 3000);
        setVal("setting-threshold-icmp", state.settingsData.icmp_flood_threshold_pps || 500);
    }

    if (noUnsaved("notifications")) {
        const d = state.settingsData;

        setChecked("setting-slack-enabled", Boolean(d.slack_webhook_url));
        setVal("setting-slack-webhook-url", d.slack_webhook_url || "");
        setChecked("setting-webhook-enabled", Boolean(d.webhook_url));
        setVal("setting-webhook-url-generic", d.webhook_url || "");
        renderWebhookHeaders(d.webhook_headers || {});

        setChecked("setting-telegram-enabled-chk", Boolean(d.telegram_enabled));
        setVal("setting-telegram-token", d.telegram_token || "");
        setVal("setting-telegram-chat-id", d.telegram_chat_id || "");
        updateTelegramUrlPreview(d.telegram_token || "");

        syncNotificationFields();
    }

    if (noUnsaved("system")) {
        setVal("setting-loglevel", state.settingsData.log_level || "info");
        setVal("setting-env", state.settingsData.environment || "production");
    }

    // Dynamic IP replacements for integrations setup guides
    const integrationsCard = document.getElementById("settings-integrations");
    if (integrationsCard) {
        const ip = getFlowGuardIP();
        if (ip && ip !== "[FLOWGUARD_IP]") {
            integrationsCard.querySelectorAll(".code-block, code, strong").forEach(el => {
                if (el.innerHTML.includes("[FLOWGUARD_IP]")) {
                    el.innerHTML = el.innerHTML.replaceAll("[FLOWGUARD_IP]", ip);
                }
            });
        }
    }

    // Clear unsaved badges only for sections not currently being edited
    Object.keys(state.unsavedChanges).forEach(k => {
        if (!state.unsavedChanges[k]) markUnsaved(k, false);
    });
    switchSettingsSection(activeSettingsSection, { confirmUnsaved: false, updateHash: false });
}

function getFlowGuardIP() {
    const hn = window.location.hostname;
    if (hn && hn !== "localhost" && hn !== "127.0.0.1" && hn !== "::1") {
        return hn;
    }
    const health = state.healthData;
    if (health && health.local_ips && health.local_ips.length > 0) {
        // Only guess standard 192.168.x.x or 10.x.x.x LAN IPs.
        // We exclude 172.16.x.x-172.31.x.x because Docker bridge networks
        // default to this range, making the container's private interface IP unreachable.
        const rfc1918 = health.local_ips.find(ip => {
            return ip.startsWith("192.168.") || ip.startsWith("10.");
        });
        if (rfc1918) return rfc1918;
    }
    return "[FLOWGUARD_IP]";
}
