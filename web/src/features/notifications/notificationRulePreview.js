import { escapeHtml } from '../../lib/format.js';

export function updateNotificationTargetFieldVisibility() {
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

    const cooldownText = cooldown > 0 ? ` with a <strong>${cooldown}s</strong> cooldown` : " without cooldown";

    textNotificationRulePreview.innerHTML = `Alerts matching ${typesText} with severity <strong>&ge; ${escapeHtml(severity)}</strong> on ${scopeText} will be routed to ${channelsText}${cooldownText}.`;
}
