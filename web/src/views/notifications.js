import { state } from '../state.js';
import { formatTime, escapeHtml } from '../utils/format.js';
import * as api from '../api.js';

export function renderNotificationRules() {
    const tblNotificationRules = document.getElementById("tbl-notification-rules").querySelector("tbody");
    if (!tblNotificationRules) return;

    if (!state.notificationRulesData || state.notificationRulesData.length === 0) {
        tblNotificationRules.innerHTML = `<tr><td colspan="7" class="text-center text-muted pad-large">No notification rules configured yet.</td></tr>`;
        return;
    }

    tblNotificationRules.innerHTML = state.notificationRulesData.map(r => {
        const isSelected = state.selectedNotificationRuleId === r.id;
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

export function renderNotificationLogs() {
    const tblNotificationLogs = document.getElementById("tbl-notification-logs").querySelector("tbody");
    if (!tblNotificationLogs) return;

    if (!state.notificationLogsData || state.notificationLogsData.length === 0) {
        tblNotificationLogs.innerHTML = `<tr><td colspan="6" class="text-center text-muted pad-large">No notification audit logs found.</td></tr>`;
        return;
    }

    tblNotificationLogs.innerHTML = state.notificationLogsData.map(log => {
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

export function selectNotificationRuleId(id) {
    state.selectedNotificationRuleId = id;
    const r = state.notificationRulesData.find(x => x.id === id);
    if (r) {
        selectNotificationRule(r);
    } else {
        resetNotificationRuleDetails();
    }
    renderNotificationRules();
}

function selectNotificationRule(r) {
    state.selectedNotificationRuleId = r.id;
    
    const inputNotificationRuleId = document.getElementById("notification-rule-id");
    const inputNotificationRuleName = document.getElementById("notification-rule-name");
    const inputNotificationRuleEnabled = document.getElementById("notification-rule-enabled");
    const selectNotificationRuleSeverity = document.getElementById("notification-rule-severity");
    const inputNotificationRuleAlertTypes = document.getElementById("notification-rule-alert-types");
    const selectNotificationRuleScope = document.getElementById("notification-rule-scope");
    const inputNotificationRuleTarget = document.getElementById("notification-rule-target");
    const inputNotificationRuleCooldown = document.getElementById("notification-rule-cooldown");
    const btnDeleteNotificationRule = document.getElementById("btn-delete-notification-rule");
    const btnTestNotificationRule = document.getElementById("btn-test-notification-rule");
    const notificationDetailsTitle = document.getElementById("notification-details-title");
    const notificationDetailsEmpty = document.getElementById("notification-details-empty");
    const notificationDetailsContent = document.getElementById("notification-details-content");

    if (inputNotificationRuleId) inputNotificationRuleId.value = r.id;
    if (inputNotificationRuleName) inputNotificationRuleName.value = r.name;
    if (inputNotificationRuleEnabled) inputNotificationRuleEnabled.checked = r.enabled;
    if (selectNotificationRuleSeverity) selectNotificationRuleSeverity.value = r.severity_min || "low";
    if (inputNotificationRuleAlertTypes) inputNotificationRuleAlertTypes.value = (r.alert_types || []).join(", ");
    if (selectNotificationRuleScope) selectNotificationRuleScope.value = r.scope;
    if (inputNotificationRuleTarget) inputNotificationRuleTarget.value = r.target || "";
    if (inputNotificationRuleCooldown) inputNotificationRuleCooldown.value = r.cooldown_seconds || "300";

    const channels = r.channel_targets || [];
    document.querySelectorAll(".rule-channel-checkbox").forEach(cb => {
        cb.checked = channels.includes(cb.value);
    });

    updateNotificationTargetFieldVisibility();

    if (btnDeleteNotificationRule) btnDeleteNotificationRule.classList.remove("hidden");
    if (btnTestNotificationRule) btnTestNotificationRule.classList.remove("hidden");

    if (notificationDetailsTitle) notificationDetailsTitle.textContent = `Edit Rule: ${r.name}`;
    if (notificationDetailsEmpty) notificationDetailsEmpty.classList.add("hidden");
    if (notificationDetailsContent) notificationDetailsContent.classList.remove("hidden");

    updateNotificationRulePreview();
}

export function startAddNotificationRule() {
    state.selectedNotificationRuleId = "new";
    
    const inputNotificationRuleId = document.getElementById("notification-rule-id");
    const inputNotificationRuleName = document.getElementById("notification-rule-name");
    const inputNotificationRuleEnabled = document.getElementById("notification-rule-enabled");
    const selectNotificationRuleSeverity = document.getElementById("notification-rule-severity");
    const inputNotificationRuleAlertTypes = document.getElementById("notification-rule-alert-types");
    const selectNotificationRuleScope = document.getElementById("notification-rule-scope");
    const inputNotificationRuleTarget = document.getElementById("notification-rule-target");
    const inputNotificationRuleCooldown = document.getElementById("notification-rule-cooldown");
    const btnDeleteNotificationRule = document.getElementById("btn-delete-notification-rule");
    const btnTestNotificationRule = document.getElementById("btn-test-notification-rule");
    const notificationDetailsTitle = document.getElementById("notification-details-title");
    const notificationDetailsEmpty = document.getElementById("notification-details-empty");
    const notificationDetailsContent = document.getElementById("notification-details-content");

    if (inputNotificationRuleId) inputNotificationRuleId.value = "";
    if (inputNotificationRuleName) inputNotificationRuleName.value = "";
    if (inputNotificationRuleEnabled) inputNotificationRuleEnabled.checked = true;
    if (selectNotificationRuleSeverity) selectNotificationRuleSeverity.value = "low";
    if (inputNotificationRuleAlertTypes) inputNotificationRuleAlertTypes.value = "";
    if (selectNotificationRuleScope) selectNotificationRuleScope.value = "global";
    if (inputNotificationRuleTarget) inputNotificationRuleTarget.value = "";
    if (inputNotificationRuleCooldown) inputNotificationRuleCooldown.value = "300";

    document.querySelectorAll(".rule-channel-checkbox").forEach(cb => {
        cb.checked = false;
    });

    updateNotificationTargetFieldVisibility();

    if (btnDeleteNotificationRule) btnDeleteNotificationRule.classList.add("hidden");
    if (btnTestNotificationRule) btnTestNotificationRule.classList.add("hidden");

    if (notificationDetailsTitle) notificationDetailsTitle.textContent = "New Notification Rule";
    if (notificationDetailsEmpty) notificationDetailsEmpty.classList.add("hidden");
    if (notificationDetailsContent) notificationDetailsContent.classList.remove("hidden");

    updateNotificationRulePreview();
    renderNotificationRules();
}

export function resetNotificationRuleDetails() {
    state.selectedNotificationRuleId = null;
    const notificationDetailsEmpty = document.getElementById("notification-details-empty");
    const notificationDetailsContent = document.getElementById("notification-details-content");
    if (notificationDetailsEmpty) notificationDetailsEmpty.classList.remove("hidden");
    if (notificationDetailsContent) notificationDetailsContent.classList.add("hidden");
}

function updateNotificationTargetFieldVisibility() {
    const selectNotificationRuleScope = document.getElementById("notification-rule-scope");
    const groupNotificationTarget = document.getElementById("group-notification-target");
    const inputNotificationRuleTarget = document.getElementById("notification-rule-target");
    const labelNotificationTarget = document.getElementById("label-notification-target");

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

export function updateNotificationRulePreview() {
    const textNotificationRulePreview = document.getElementById("notification-rule-preview");
    if (!textNotificationRulePreview) return;

    const inputNotificationRuleName = document.getElementById("notification-rule-name");
    const inputNotificationRuleEnabled = document.getElementById("notification-rule-enabled");
    const selectNotificationRuleSeverity = document.getElementById("notification-rule-severity");
    const inputNotificationRuleAlertTypes = document.getElementById("notification-rule-alert-types");
    const selectNotificationRuleScope = document.getElementById("notification-rule-scope");
    const inputNotificationRuleTarget = document.getElementById("notification-rule-target");
    const inputNotificationRuleCooldown = document.getElementById("notification-rule-cooldown");

    if (!inputNotificationRuleName || !inputNotificationRuleEnabled || !selectNotificationRuleSeverity || !selectNotificationRuleScope || !inputNotificationRuleCooldown) return;

    const enabled = inputNotificationRuleEnabled.checked;
    const severity = selectNotificationRuleSeverity.value;
    const alertTypesStr = inputNotificationRuleAlertTypes ? inputNotificationRuleAlertTypes.value.trim() : "";
    const scope = selectNotificationRuleScope.value;
    const target = inputNotificationRuleTarget ? inputNotificationRuleTarget.value.trim() : "";
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

export function renderNotificationsView() {
    renderNotificationRules();
    renderNotificationLogs();
    if (state.selectedNotificationRuleId && state.selectedNotificationRuleId !== "new") {
        selectNotificationRuleId(state.selectedNotificationRuleId);
    } else if (state.selectedNotificationRuleId === "new") {
        startAddNotificationRule();
    } else {
        resetNotificationRuleDetails();
    }
}

export function bindNotificationsEvents(onReload) {
    const btnAddRule = document.getElementById("btn-add-notification-rule");
    if (btnAddRule) {
        btnAddRule.addEventListener("click", startAddNotificationRule);
    }

    const btnCancelRule = document.getElementById("btn-cancel-notification-rule");
    if (btnCancelRule) {
        btnCancelRule.addEventListener("click", () => {
            resetNotificationRuleDetails();
            renderNotificationRules();
        });
    }

    const btnDeleteRule = document.getElementById("btn-delete-notification-rule");
    if (btnDeleteRule) {
        btnDeleteRule.addEventListener("click", async () => {
            const inputNotificationRuleId = document.getElementById("notification-rule-id");
            if (!inputNotificationRuleId || !inputNotificationRuleId.value) return;
            const id = inputNotificationRuleId.value;

            if (!confirm("Are you sure you want to delete this notification rule?")) return;

            try {
                await api.deleteNotificationRule(id);
                window.showToast("Notification rule deleted successfully");
                state.selectedNotificationRuleId = null;
                resetNotificationRuleDetails();
                if (onReload) await onReload();
            } catch (err) {
                window.showToast(err.message, "error");
            }
        });
    }

    const btnTestRule = document.getElementById("btn-test-notification-rule");
    if (btnTestRule) {
        btnTestRule.addEventListener("click", async () => {
            const inputNotificationRuleId = document.getElementById("notification-rule-id");
            if (!inputNotificationRuleId || !inputNotificationRuleId.value) return;
            const id = inputNotificationRuleId.value;

            window.showToast("Sending test alert for rule...", "info");
            try {
                await api.testNotificationRule(id);
                window.showToast("Test alert sent.");
            } catch (err) {
                window.showToast("Test alert failed: " + err.message, "error");
            }
        });
    }

    const btnCloseRuleDetails = document.getElementById("btn-close-notification-rule-details");
    if (btnCloseRuleDetails) {
        btnCloseRuleDetails.addEventListener("click", () => {
            resetNotificationRuleDetails();
            renderNotificationRules();
        });
    }

    const selectRuleScope = document.getElementById("notification-rule-scope");
    if (selectRuleScope) {
        selectRuleScope.addEventListener("change", () => {
            updateNotificationTargetFieldVisibility();
            updateNotificationRulePreview();
        });
    }

    const formNotificationRuleEditor = document.getElementById("form-notification-rule-editor");
    if (formNotificationRuleEditor) {
        formNotificationRuleEditor.addEventListener("submit", async (e) => {
            e.preventDefault();

            const inputNotificationRuleId = document.getElementById("notification-rule-id");
            const inputNotificationRuleName = document.getElementById("notification-rule-name");
            const inputNotificationRuleEnabled = document.getElementById("notification-rule-enabled");
            const selectNotificationRuleSeverity = document.getElementById("notification-rule-severity");
            const inputNotificationRuleAlertTypes = document.getElementById("notification-rule-alert-types");
            const selectNotificationRuleScope = document.getElementById("notification-rule-scope");
            const inputNotificationRuleTarget = document.getElementById("notification-rule-target");
            const inputNotificationRuleCooldown = document.getElementById("notification-rule-cooldown");

            const id = inputNotificationRuleId ? inputNotificationRuleId.value : "";
            const name = inputNotificationRuleName ? inputNotificationRuleName.value.trim() : "";
            const enabled = inputNotificationRuleEnabled ? inputNotificationRuleEnabled.checked : false;
            const severityMin = selectNotificationRuleSeverity ? selectNotificationRuleSeverity.value : "low";
            const alertTypesVal = inputNotificationRuleAlertTypes ? inputNotificationRuleAlertTypes.value.trim() : "";
            const scope = selectNotificationRuleScope ? selectNotificationRuleScope.value : "global";
            const target = inputNotificationRuleTarget ? inputNotificationRuleTarget.value.trim() : "";
            const cooldownSeconds = inputNotificationRuleCooldown ? parseInt(inputNotificationRuleCooldown.value) : 300;

            const channelTargets = [];
            document.querySelectorAll(".rule-channel-checkbox").forEach(cb => {
                if (cb.checked) channelTargets.push(cb.value);
            });

            if (!name) {
                window.showToast("Rule name is required", "error");
                return;
            }

            if (scope === "ip" && !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target)) {
                window.showToast("Target must be a valid IPv4 address", "error");
                return;
            }

            if (scope === "subnet" && !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/.test(target)) {
                window.showToast("Target must be a valid CIDR network block (e.g. 192.168.1.0/24)", "error");
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
                await api.saveNotificationRule(payload);
                window.showToast(`Notification rule saved successfully`);
                if (onReload) await onReload();
            } catch (err) {
                window.showToast(err.message, "error");
            }
        });
    }

    const inputNotificationRuleName = document.getElementById("notification-rule-name");
    const inputNotificationRuleEnabled = document.getElementById("notification-rule-enabled");
    const selectNotificationRuleSeverity = document.getElementById("notification-rule-severity");
    const inputNotificationRuleAlertTypes = document.getElementById("notification-rule-alert-types");
    const inputNotificationRuleTarget = document.getElementById("notification-rule-target");
    const inputNotificationRuleCooldown = document.getElementById("notification-rule-cooldown");

    const formRuleInputs = [
        inputNotificationRuleName,
        inputNotificationRuleEnabled,
        selectNotificationRuleSeverity,
        inputNotificationRuleAlertTypes,
        inputNotificationRuleTarget,
        inputNotificationRuleCooldown
    ];
    formRuleInputs.forEach(input => {
        if (input) {
            input.addEventListener("input", updateNotificationRulePreview);
            input.addEventListener("change", updateNotificationRulePreview);
        }
    });
    document.querySelectorAll(".rule-channel-checkbox").forEach(cb => {
        cb.addEventListener("change", updateNotificationRulePreview);
    });
}
