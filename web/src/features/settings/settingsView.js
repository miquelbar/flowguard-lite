import { state } from '../../app/state.js';
import * as api from '../../lib/api.js';
import { setNormalizedTrafficRange } from '../../lib/timeRanges.js';
import { markUnsaved, switchSettingsSection } from './settingsSections.js';
import { bindBackupEvents } from './settingsBackup.js';
import { bindNotificationDiagnostics } from './settingsDiagnostics.js';
import { appendWebhookHeaderRow, syncNotificationFields, updateTelegramUrlPreview } from './settingsNotifications.js';
import { bindThresholdControlEvents } from './settingsThresholdControls.js';

export { renderSettingsView } from './settingsRender.js';

function csvListValue(id) {
    return (document.getElementById(id)?.value || "")
        .split(",")
        .map(item => item.trim())
        .filter(Boolean);
}

export function bindSettingsEvents(onReload) {
    const slackEnabledChk = document.getElementById("setting-slack-enabled");
    if (slackEnabledChk) {
        slackEnabledChk.addEventListener("change", () => {
            syncNotificationFields();
            markUnsaved("notifications", true);
        });
    }

    const webhookEnabledChk = document.getElementById("setting-webhook-enabled");
    if (webhookEnabledChk) {
        webhookEnabledChk.addEventListener("change", () => {
            syncNotificationFields();
            markUnsaved("notifications", true);
        });
    }

    const telegramEnabledChk = document.getElementById("setting-telegram-enabled-chk");
    if (telegramEnabledChk) {
        telegramEnabledChk.addEventListener("change", () => {
            syncNotificationFields();
            markUnsaved("notifications", true);
        });
    }

    const telegramToken = document.getElementById("setting-telegram-token");
    if (telegramToken) {
        telegramToken.addEventListener("input", () => {
            updateTelegramUrlPreview(telegramToken.value.trim());
        });
    }

    bindNotificationDiagnostics();
    bindThresholdControlEvents(() => markUnsaved("thresholds", true));

    const btnAddWebhookHeader = document.getElementById("btn-add-webhook-header");
    if (btnAddWebhookHeader) {
        btnAddWebhookHeader.addEventListener("click", () => {
            appendWebhookHeaderRow("", "");
            markUnsaved("notifications", true);
        });
    }

    // Access submit
    const formSettingsAccess = document.getElementById("form-settings-access");
    if (formSettingsAccess) {
        formSettingsAccess.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!state.settingsData) return;
            const password = document.getElementById("setting-access-password").value;
            const confirm = document.getElementById("setting-access-confirm").value;
            if (password !== confirm) {
                window.showToast("Passwords do not match", "error");
                return;
            }
            if (password.length > 0 && password.length < 10) {
                window.showToast("Password must be at least 10 characters long", "error");
                return;
            }
            const payload = {
                ...state.settingsData,
                admin_password: password
            };
            try {
                await api.saveSettings("access", payload);
                let note = "";
                window.showToast("Access settings saved successfully." + note);
                state.settingsData = await api.fetchSettings();
                markUnsaved("access", false);
                document.getElementById("setting-access-password").value = "";
                document.getElementById("setting-access-confirm").value = "";
            } catch (err) {
                window.showToast("Settings save failed: " + err.message, "error");
            }
        });
    }

    // Network submit
    const formSettingsNetwork = document.getElementById("form-settings-network");
    if (formSettingsNetwork) {
        formSettingsNetwork.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!state.settingsData) return;
            const port = document.getElementById("setting-port").value.trim();
            const subnets = document.getElementById("setting-subnets").value.split(",").map(s => s.trim()).filter(s => s !== "");
            const payload = {
                ...state.settingsData,
                port: port,
                local_subnets: subnets
            };
            try {
                await api.saveSettings("network", payload);
                let note = "";
                if (payload.port !== state.settingsData.port) {
                    note = " (Note: Port changes require a daemon restart)";
                }
                window.showToast("Network settings saved successfully." + note);
                state.settingsData = await api.fetchSettings();
                markUnsaved("network", false);
            } catch (err) {
                window.showToast("Settings save failed: " + err.message, "error");
            }
        });
    }

    // Collectors submit
    const formSettingsCollectors = document.getElementById("form-settings-collectors");
    if (formSettingsCollectors) {
        formSettingsCollectors.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!state.settingsData) return;
            const netflow = parseInt(document.getElementById("setting-netflow").value, 10);
            const sflow = parseInt(document.getElementById("setting-sflow").value, 10);
            const unifiSyslogEnabled = document.getElementById("setting-unifi-syslog-enabled").checked;
            const unifiSyslogPort = parseInt(document.getElementById("setting-unifi-syslog-port").value, 10);
            const unifiSyslogAllowed = document.getElementById("setting-unifi-syslog-allowed").value
                .split(",")
                .map(item => item.trim())
                .filter(Boolean);
            const suricata = document.getElementById("setting-suricata-path").value.trim();
            const captureInterface = document.getElementById("setting-capture-interface").value.trim();
            const captureBPFFilter = document.getElementById("setting-capture-bpf-filter").value.trim();
            const capturePromiscuous = document.getElementById("setting-capture-promiscuous").checked;
            if (Number.isNaN(netflow) || netflow < 0 || netflow > 65535 ||
                Number.isNaN(sflow) || sflow < 0 || sflow > 65535 ||
                Number.isNaN(unifiSyslogPort) || unifiSyslogPort < 0 || unifiSyslogPort > 65535) {
                window.showToast("Collector ports must be between 0 and 65535.", "error");
                return;
            }
            if (unifiSyslogEnabled && unifiSyslogPort === 0) {
                window.showToast("UniFi SIEM/syslog port must be greater than 0 when enabled.", "error");
                return;
            }
            if (captureInterface && !captureBPFFilter) {
                window.showToast("A BPF filter is required when passive capture is enabled.", "error");
                return;
            }
            const payload = {
                ...state.settingsData,
                netflow_port: netflow,
                sflow_port: sflow,
                unifi_syslog_enabled: unifiSyslogEnabled,
                unifi_syslog_port: unifiSyslogPort,
                unifi_syslog_allowed_ips: unifiSyslogAllowed,
                suricata_eve_path: suricata,
                capture_interface: captureInterface,
                capture_bpf_filter: captureBPFFilter,
                capture_promiscuous: capturePromiscuous
            };
            try {
                await api.saveSettings("collectors", payload);
                let note = "";
                if (payload.netflow_port !== state.settingsData.netflow_port ||
                    payload.sflow_port !== state.settingsData.sflow_port ||
                    payload.unifi_syslog_enabled !== state.settingsData.unifi_syslog_enabled ||
                    payload.unifi_syslog_port !== state.settingsData.unifi_syslog_port ||
                    payload.unifi_syslog_allowed_ips.join(",") !== (state.settingsData.unifi_syslog_allowed_ips || []).join(",") ||
                    payload.capture_interface !== state.settingsData.capture_interface ||
                    payload.capture_bpf_filter !== state.settingsData.capture_bpf_filter ||
                    payload.capture_promiscuous !== state.settingsData.capture_promiscuous) {
                    note = " (Note: Collector and passive capture changes require a daemon restart)";
                }
                window.showToast("Collectors settings saved successfully." + note);
                state.settingsData = await api.fetchSettings();
                markUnsaved("collectors", false);
            } catch (err) {
                window.showToast("Settings save failed: " + err.message, "error");
            }
        });
    }

    // Storage submit
    const formSettingsStorage = document.getElementById("form-settings-storage");
    if (formSettingsStorage) {
        formSettingsStorage.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!state.settingsData) return;
            const dir = document.getElementById("setting-storage-dir").value.trim();
            const backend = document.getElementById("setting-backend").value;
            const retention = parseInt(document.getElementById("setting-retention").value, 10);
            const payload = {
                ...state.settingsData,
                storage_dir: dir,
                storage_backend: backend,
                retention_days: retention
            };
            try {
                await api.saveSettings("storage", payload);
                let note = "";
                if (payload.storage_dir !== state.settingsData.storage_dir || payload.storage_backend !== state.settingsData.storage_backend) {
                    note = " (Note: Storage backend and directory changes require a daemon restart)";
                }
                window.showToast("Storage settings saved successfully." + note);
                state.settingsData = await api.fetchSettings();
                setNormalizedTrafficRange();
                markUnsaved("storage", false);
            } catch (err) {
                window.showToast("Settings save failed: " + err.message, "error");
            }
        });
    }

    // Thresholds submit
    const formSettingsThresholds = document.getElementById("form-settings-thresholds");
    if (formSettingsThresholds) {
        formSettingsThresholds.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!state.settingsData) return;
            const disabledAnomalyTypes = csvListValue("setting-disabled-anomaly-types");
            const mutedAnomalySubnets = csvListValue("setting-muted-anomaly-subnets");
            const notifyAllowedSubnets = csvListValue("setting-notify-allowed-subnets");
            const notifySuppressedTypes = csvListValue("setting-notify-suppressed-types");
            const newDestinationHistory = parseInt(document.getElementById("setting-new-destination-history").value, 10);
            const beaconObservations = parseInt(document.getElementById("setting-beacon-observations").value, 10);
            const beaconMinInterval = parseInt(document.getElementById("setting-beacon-min-interval").value, 10);
            const trafficSpikeMinPackets = parseInt(document.getElementById("setting-traffic-spike-min-packets").value, 10);
            const trafficSpikeMinBytes = parseInt(document.getElementById("setting-traffic-spike-min-bytes").value, 10);
            const pps = parseInt(document.getElementById("setting-threshold-pps").value, 10);
            const bps = parseInt(document.getElementById("setting-threshold-bps").value, 10);
            const fps = parseInt(document.getElementById("setting-threshold-fps").value, 10);
            const syn = parseInt(document.getElementById("setting-threshold-syn").value, 10);
            const udp = parseInt(document.getElementById("setting-threshold-udp").value, 10);
            const icmp = parseInt(document.getElementById("setting-threshold-icmp").value, 10);
            const allNumbers = [newDestinationHistory, beaconObservations, beaconMinInterval, trafficSpikeMinPackets, trafficSpikeMinBytes, pps, bps, fps, syn, udp, icmp];
            if (allNumbers.some(v => Number.isNaN(v) || v < 1)) {
                window.showToast("Detection thresholds must be positive numbers.", "error");
                return;
            }
            const payload = {
                ...state.settingsData,
                disabled_anomaly_types: disabledAnomalyTypes,
                muted_anomaly_subnets: mutedAnomalySubnets,
                notify_allowed_subnets: notifyAllowedSubnets,
                notify_suppressed_types: notifySuppressedTypes,
                new_destination_min_history_buckets: newDestinationHistory,
                beacon_min_observations: beaconObservations,
                beacon_min_interval_seconds: beaconMinInterval,
                traffic_spike_min_packets: trafficSpikeMinPackets,
                traffic_spike_min_bytes: trafficSpikeMinBytes,
                ddos_threshold_pps: pps,
                ddos_threshold_bps: bps,
                ddos_threshold_fps: fps,
                syn_flood_threshold_pps: syn,
                udp_flood_threshold_pps: udp,
                icmp_flood_threshold_pps: icmp
            };
            try {
                await api.saveSettings("thresholds", payload);
                window.showToast("Threshold settings saved successfully.");
                state.settingsData = await api.fetchSettings();
                markUnsaved("thresholds", false);
            } catch (err) {
                window.showToast("Settings save failed: " + err.message, "error");
            }
        });
    }

    // Webhook / Notifications submit
    const formSettingsWebhook = document.getElementById("form-settings-webhook");
    if (formSettingsWebhook) {
        formSettingsWebhook.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!state.settingsData) return;

            const slackEnabled = document.getElementById("setting-slack-enabled")?.checked;
            const slackWebhookUrl = slackEnabled ? document.getElementById("setting-slack-webhook-url")?.value.trim() || "" : "";
            const webhookEnabled = document.getElementById("setting-webhook-enabled")?.checked;
            let webhookUrl = "";
            let webhookHeaders = {};

            if (webhookEnabled) {
                webhookUrl = document.getElementById("setting-webhook-url-generic")?.value.trim() || "";
                const headerRows = document.querySelectorAll("#webhook-headers-list .webhook-header-row");
                headerRows.forEach(row => {
                    const key = row.querySelector(".header-key")?.value.trim();
                    const val = row.querySelector(".header-value")?.value.trim();
                    if (key) webhookHeaders[key] = val;
                });
            }

            const telegramEnabled = document.getElementById("setting-telegram-enabled-chk")?.checked;
            const telegramToken = document.getElementById("setting-telegram-token")?.value.trim() || "";
            const telegramChatId = document.getElementById("setting-telegram-chat-id")?.value.trim() || "";

            const payload = {
                ...state.settingsData,
                slack_webhook_url: slackWebhookUrl,
                webhook_url:      webhookUrl,
                webhook_format:   "generic",
                webhook_headers:  webhookHeaders,
                telegram_enabled: telegramEnabled,
                telegram_token:   telegramToken,
                telegram_chat_id: telegramChatId
            };

            try {
                await api.saveSettings("notifications", payload);
                window.showToast("Notification settings saved successfully.");
                state.settingsData = await api.fetchSettings();
                markUnsaved("notifications", false);
            } catch (err) {
                window.showToast("Settings save failed: " + err.message, "error");
            }
        });
    }

    // System submit
    const formSettingsSystem = document.getElementById("form-settings-system");
    if (formSettingsSystem) {
        formSettingsSystem.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!state.settingsData) return;
            const loglevel = document.getElementById("setting-loglevel").value;
            const env = document.getElementById("setting-env").value;
            const payload = {
                ...state.settingsData,
                log_level: loglevel,
                environment: env
            };
            try {
                await api.saveSettings("system", payload);
                window.showToast("System settings saved successfully.");
                state.settingsData = await api.fetchSettings();
                markUnsaved("system", false);
            } catch (err) {
                window.showToast("Settings save failed: " + err.message, "error");
            }
        });
    }

    // Integrations guide tabs switching
    const integrationCard = document.getElementById("settings-integrations");
    if (integrationCard) {
        integrationCard.querySelectorAll(".integration-tabs .tab-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                integrationCard.querySelectorAll(".integration-tabs .tab-btn").forEach(t => t.classList.remove("active"));
                btn.classList.add("active");
                integrationCard.querySelectorAll(".integration-guide-content").forEach(g => g.classList.add("hidden"));
                const targetGuide = btn.getAttribute("data-guide");
                const targetEl = document.getElementById(`guide-${targetGuide}`);
                if (targetEl) {
                    targetEl.classList.remove("hidden");
                }
            });
        });
    }

    // Navigation section links
    document.querySelectorAll(".settings-nav .settings-nav-link").forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const sec = link.getAttribute("data-section");
            switchSettingsSection(sec);
        });
    });

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

    bindBackupEvents();
}
