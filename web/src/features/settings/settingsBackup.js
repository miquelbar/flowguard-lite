import { state } from '../../app/state.js';
import * as api from '../../lib/api.js';
import { escapeHtml } from '../../lib/format.js';
import { normalizeBackupConfig } from './settingsBackupValidation.js';

let pendingImportConfig = null;

export function bindBackupEvents() {
    const btnExport = document.getElementById("btn-export-backup");
    if (btnExport) {
        btnExport.addEventListener("click", async () => {
            try {
                btnExport.disabled = true;
                btnExport.textContent = "Exporting...";

                const settings = await api.fetchSettings();
                const policies = await api.fetchPolicies();
                const notificationRules = await api.fetchNotificationRules();

                const backup = {
                    version: "1.0",
                    timestamp: new Date().toISOString(),
                    settings: {
                        port: settings.port || "8080",
                        local_subnets: settings.local_subnets || [],
                        netflow_port: settings.netflow_port || 0,
                        sflow_port: settings.sflow_port || 0,
                        unifi_syslog_enabled: settings.unifi_syslog_enabled || false,
                        unifi_syslog_port: settings.unifi_syslog_port || 5514,
                        unifi_syslog_allowed_ips: settings.unifi_syslog_allowed_ips || [],
                        suricata_eve_path: settings.suricata_eve_path || "",
                        capture_interface: settings.capture_interface || "",
                        capture_bpf_filter: settings.capture_bpf_filter || "ip or ip6",
                        capture_promiscuous: settings.capture_promiscuous || false,
                        storage_dir: settings.storage_dir || "/data",
                        storage_backend: settings.storage_backend || "sqlite",
                        retention_days: settings.retention_days || 7,
                        disabled_anomaly_types: settings.disabled_anomaly_types || [],
                        muted_anomaly_subnets: settings.muted_anomaly_subnets || [],
                        notify_allowed_subnets: settings.notify_allowed_subnets || [],
                        notify_suppressed_types: settings.notify_suppressed_types || [],
                        new_destination_min_history_buckets: settings.new_destination_min_history_buckets || 12,
                        beacon_min_observations: settings.beacon_min_observations || 12,
                        beacon_min_interval_seconds: settings.beacon_min_interval_seconds || 90,
                        traffic_spike_min_packets: settings.traffic_spike_min_packets || 2500,
                        traffic_spike_min_bytes: settings.traffic_spike_min_bytes || 1048576,
                        ddos_threshold_pps: settings.ddos_threshold_pps || 5000,
                        ddos_threshold_bps: settings.ddos_threshold_bps || 10000000,
                        ddos_threshold_fps: settings.ddos_threshold_fps || 1000,
                        syn_flood_threshold_pps: settings.syn_flood_threshold_pps || 1000,
                        udp_flood_threshold_pps: settings.udp_flood_threshold_pps || 3000,
                        icmp_flood_threshold_pps: settings.icmp_flood_threshold_pps || 500,
                        telegram_enabled: settings.telegram_enabled || false,
                        telegram_token: settings.telegram_token || "",
                        telegram_chat_id: settings.telegram_chat_id || "",
                        slack_webhook_url: settings.slack_webhook_url || "",
                        webhook_format: settings.webhook_format || "generic",
                        webhook_url: settings.webhook_url || "",
                        webhook_headers: settings.webhook_headers || {},
                        log_level: settings.log_level || "info",
                        environment: settings.environment || "production"
                    },
                    policies: (policies || []).map(p => ({
                        name: p.name,
                        scope: p.scope,
                        target: p.target,
                        severity_threshold: p.severity_threshold,
                        cooldown_seconds: p.cooldown_seconds,
                        quiet_hours_start: p.quiet_hours_start,
                        quiet_hours_end: p.quiet_hours_end,
                        suppressed: p.suppressed,
                        notification_channels: p.notification_channels || []
                    })),
                    notification_rules: (notificationRules || []).map(r => ({
                        name: r.name,
                        scope: r.scope,
                        target: r.target,
                        channels: r.channels || []
                    }))
                };

                const dataStr = JSON.stringify(backup, null, 2);
                const blob = new Blob([dataStr], { type: "application/json" });
                const url = URL.createObjectURL(blob);

                const dateStr = new Date().toISOString().split('T')[0];
                const link = document.createElement("a");
                link.href = url;
                link.download = `flowguard-backup-${dateStr}.json`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);

                window.showToast("Backup exported successfully.");
            } catch (err) {
                window.showToast("Backup export failed: " + err.message, "error");
            } finally {
                btnExport.disabled = false;
                btnExport.textContent = "Export Configuration (JSON)";
            }
        });
    }

    const inputImport = document.getElementById("input-import-file");
    if (inputImport) {
        inputImport.addEventListener("change", (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = (event) => {
                try {
                    const data = JSON.parse(event.target.result);
                    validateAndPreviewConfig(data);
                } catch (err) {
                    showImportError("Invalid JSON structure: " + err.message);
                }
            };
            reader.readAsText(file);
        });
    }

    const btnConfirmImport = document.getElementById("btn-confirm-import");
    if (btnConfirmImport) {
        btnConfirmImport.addEventListener("click", async () => {
            if (!pendingImportConfig) return;
            try {
                btnConfirmImport.disabled = true;
                btnConfirmImport.textContent = "Applying config...";

                const s = pendingImportConfig.settings;
                const currentSettings = await api.fetchSettings();

                const networkPayload = { ...currentSettings, port: s.port, local_subnets: s.local_subnets };
                const collectorsPayload = {
                    ...currentSettings,
                    netflow_port: s.netflow_port,
                    sflow_port: s.sflow_port,
                    unifi_syslog_enabled: s.unifi_syslog_enabled,
                    unifi_syslog_port: s.unifi_syslog_port,
                    unifi_syslog_allowed_ips: s.unifi_syslog_allowed_ips,
                    suricata_eve_path: s.suricata_eve_path,
                    capture_interface: s.capture_interface,
                    capture_bpf_filter: s.capture_bpf_filter,
                    capture_promiscuous: s.capture_promiscuous
                };
                const storagePayload = {
                    ...currentSettings,
                    storage_dir: s.storage_dir,
                    storage_backend: s.storage_backend,
                    retention_days: s.retention_days
                };
                const thresholdsPayload = {
                    ...currentSettings,
                    ddos_threshold_pps: s.ddos_threshold_pps,
                    ddos_threshold_bps: s.ddos_threshold_bps,
                    ddos_threshold_fps: s.ddos_threshold_fps,
                    syn_flood_threshold_pps: s.syn_flood_threshold_pps,
                    udp_flood_threshold_pps: s.udp_flood_threshold_pps,
                    icmp_flood_threshold_pps: s.icmp_flood_threshold_pps
                };
                const notificationsPayload = {
                    ...currentSettings,
                    telegram_enabled: s.telegram_enabled,
                    telegram_token: s.telegram_token,
                    telegram_chat_id: s.telegram_chat_id,
                    slack_webhook_url: s.slack_webhook_url,
                    webhook_format: s.webhook_format,
                    webhook_url: s.webhook_url,
                    webhook_headers: s.webhook_headers
                };
                const systemPayload = {
                    ...currentSettings,
                    log_level: s.log_level,
                    environment: s.environment
                };

                await api.saveSettings("network", networkPayload);
                await api.saveSettings("collectors", collectorsPayload);
                await api.saveSettings("storage", storagePayload);
                await api.saveSettings("thresholds", thresholdsPayload);
                await api.saveSettings("notifications", notificationsPayload);
                await api.saveSettings("system", systemPayload);

                const currentPolicies = await api.fetchPolicies();
                for (const p of currentPolicies) {
                    await api.deletePolicy(p.id);
                }
                for (const p of pendingImportConfig.policies || []) {
                    await api.savePolicy(p);
                }

                const currentRules = await api.fetchNotificationRules();
                for (const r of currentRules) {
                    await api.deleteNotificationRule(r.id);
                }
                for (const r of pendingImportConfig.notification_rules || []) {
                    await api.saveNotificationRule(r);
                }

                window.showToast("Configuration backup restored successfully.");
                resetImportState();

                // Refresh settings view data
                state.settingsData = await api.fetchSettings();
                state.policiesData = await api.fetchPolicies();
                state.notificationRulesData = await api.fetchNotificationRules();

                window.location.hash = "#/settings/system";
            } catch (err) {
                window.showToast("Configuration import failed: " + err.message, "error");
            } finally {
                btnConfirmImport.disabled = false;
                btnConfirmImport.textContent = "Apply Configuration";
            }
        });
    }
}

function showImportError(msg) {
    const area = document.getElementById("import-preview-area");
    const summary = document.getElementById("import-preview-summary");
    const warning = document.getElementById("import-preview-warning");
    const btnConfirm = document.getElementById("btn-confirm-import");

    if (area) area.classList.remove("hidden");
    if (summary) {
        summary.classList.add("text-danger", "font-semibold");
        summary.textContent = `Error: ${msg}`;
    }
    if (warning) warning.classList.add("hidden");
    if (btnConfirm) btnConfirm.style.display = "none";
    pendingImportConfig = null;
}

function resetImportState() {
    const area = document.getElementById("import-preview-area");
    const inputImport = document.getElementById("input-import-file");
    if (area) area.classList.add("hidden");
    if (inputImport) inputImport.value = "";
    pendingImportConfig = null;
}

function validateAndPreviewConfig(data) {
    if (typeof data !== "object" || data === null) {
        showImportError("Backup data must be a JSON object.");
        return;
    }
    if (!data.version) {
        showImportError("Missing 'version' metadata string.");
        return;
    }
    if (typeof data.settings !== "object" || data.settings === null) {
        showImportError("Missing or invalid 'settings' configuration object.");
        return;
    }

    const normalized = normalizeBackupConfig(data);
    if (normalized.error) {
        showImportError(normalized.error);
        return;
    }
    const sanitized = normalized.value;
    const s = sanitized.settings;

    pendingImportConfig = sanitized;

    const area = document.getElementById("import-preview-area");
    const summary = document.getElementById("import-preview-summary");
    const warning = document.getElementById("import-preview-warning");
    const btnConfirm = document.getElementById("btn-confirm-import");

    if (area) area.classList.remove("hidden");
    if (btnConfirm) btnConfirm.style.display = "block";

    const policiesCount = sanitized.policies.length;
    const rulesCount = sanitized.notification_rules.length;

    let previewHtml = `
        <ul class="import-preview-list">
            <li><strong>Port:</strong> <code>${escapeHtml(s.port || "8080")}</code></li>
            <li><strong>Subnets:</strong> <code>${escapeHtml((s.local_subnets || []).join(", ") || "none")}</code></li>
            <li><strong>Policies:</strong> <code>${policiesCount}</code> rules to restore</li>
            <li><strong>Alert Dispatch Rules:</strong> <code>${rulesCount}</code> channels to configure</li>
        </ul>
    `;
    summary.classList.remove("text-danger", "font-semibold");
    summary.innerHTML = previewHtml;

    let warningText = "";
    if (s.port && s.port !== state.settingsData.port) {
        warningText += "Warning: Changing web server HTTP port requires a daemon restart.<br>";
    }
    if (policiesCount > 0) {
        warningText += "Warning: This import will clear all currently active Policies and replace them.<br>";
    }
    if (rulesCount > 0) {
        warningText += "Warning: This import will clear all currently active Alert Dispatch channels/rules and replace them.<br>";
    }

    if (warningText) {
        warning.innerHTML = warningText;
        warning.classList.remove("hidden");
    } else {
        warning.classList.add("hidden");
    }
}
