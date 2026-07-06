import { state } from '../state.js';
import * as api from '../api.js';

let activeSettingsSection = "access";

export function renderSettingsView() {
    if (!state.settingsData) return;

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
        setVal("setting-suricata-path", state.settingsData.suricata_eve_path || "");
    }

    if (noUnsaved("storage")) {
        setVal("setting-storage-dir", state.settingsData.storage_dir || "/data");
        setVal("setting-backend", state.settingsData.storage_backend);
        setVal("setting-retention", state.settingsData.retention_days || 7);
    }

    if (noUnsaved("thresholds")) {
        setVal("setting-threshold-pps", state.settingsData.ddos_threshold_pps || 5000);
        setVal("setting-threshold-bps", state.settingsData.ddos_threshold_bps || 10000000);
        setVal("setting-threshold-syn", state.settingsData.syn_flood_threshold_pps || 1000);
        setVal("setting-threshold-udp", state.settingsData.udp_flood_threshold_pps || 3000);
        setVal("setting-threshold-icmp", state.settingsData.icmp_flood_threshold_pps || 500);
    }

    if (noUnsaved("notifications")) {
        setVal("setting-webhook-url", state.settingsData.webhook_url || "");
        setVal("setting-webhook-format", state.settingsData.webhook_format || "generic");
        setVal("setting-telegram-token", state.settingsData.telegram_token || "");
        setVal("setting-telegram-chat-id", state.settingsData.telegram_chat_id || "");
        const tgEnabled = document.getElementById("setting-telegram-enabled");
        if (tgEnabled) tgEnabled.checked = !!state.settingsData.telegram_enabled;
        if (noUnsaved("notifications")) {
            renderWebhookHeaders(state.settingsData.webhook_headers || {});
        }
    }

    if (noUnsaved("system")) {
        setVal("setting-loglevel", state.settingsData.log_level || "info");
        setVal("setting-env", state.settingsData.environment || "production");
    }

    // Clear unsaved badges only for sections not currently being edited
    Object.keys(state.unsavedChanges).forEach(k => {
        if (!state.unsavedChanges[k]) markUnsaved(k, false);
    });
}


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
    if (state.unsavedChanges[activeSettingsSection]) {
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
    state.unsavedChanges[section] = isUnsaved;
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
    keyInput.addEventListener("input", () => markUnsaved("notifications", true));

    const valueInput = document.createElement("input");
    valueInput.type = "text";
    valueInput.placeholder = "Value";
    valueInput.className = "form-control header-value";
    valueInput.value = val;
    valueInput.style.cssText = "flex: 2; height: 32px; font-size: 0.8rem; padding: 0 0.5rem;";
    valueInput.addEventListener("input", () => markUnsaved("notifications", true));

    const removeButton = document.createElement("button");
    removeButton.type = "button";
    removeButton.className = "btn-secondary btn-remove-header";
    removeButton.textContent = "x";
    removeButton.style.cssText = "height: 32px; width: 32px; padding: 0; line-height: 30px; font-size: 1.1rem; text-align: center; border-radius: 6px; cursor: pointer; flex-shrink: 0;";
    removeButton.addEventListener("click", () => {
        row.remove();
        markUnsaved("notifications", true);
    });

    row.append(keyInput, valueInput, removeButton);
    listContainer.appendChild(row);
}

export function bindSettingsEvents(onReload) {
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
            const suricata = document.getElementById("setting-suricata-path").value.trim();
            const payload = {
                ...state.settingsData,
                netflow_port: netflow,
                sflow_port: sflow,
                suricata_eve_path: suricata
            };
            try {
                await api.saveSettings("collectors", payload);
                let note = "";
                if (payload.netflow_port !== state.settingsData.netflow_port || payload.sflow_port !== state.settingsData.sflow_port) {
                    note = " (Note: Collector port changes require a daemon restart)";
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
            const pps = parseInt(document.getElementById("setting-threshold-pps").value, 10);
            const bps = parseInt(document.getElementById("setting-threshold-bps").value, 10);
            const syn = parseInt(document.getElementById("setting-threshold-syn").value, 10);
            const udp = parseInt(document.getElementById("setting-threshold-udp").value, 10);
            const icmp = parseInt(document.getElementById("setting-threshold-icmp").value, 10);
            const payload = {
                ...state.settingsData,
                ddos_threshold_pps: pps,
                ddos_threshold_bps: bps,
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

    // Webhook submit
    const formSettingsWebhook = document.getElementById("form-settings-webhook");
    if (formSettingsWebhook) {
        formSettingsWebhook.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!state.settingsData) return;
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
                ...state.settingsData,
                webhook_url: url,
                webhook_format: format,
                webhook_headers: headers,
                telegram_enabled: tgEnabled,
                telegram_token: tgToken,
                telegram_chat_id: tgChatId
            };
            try {
                await api.saveSettings("notifications", payload);
                window.showToast("Routing & notification settings saved successfully.");
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

    // Navigation section links
    document.querySelectorAll(".settings-nav .settings-nav-link").forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const sec = link.getAttribute("data-section");
            if (sec === "integrations") {
                if (state.unsavedChanges[activeSettingsSection]) {
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
}
