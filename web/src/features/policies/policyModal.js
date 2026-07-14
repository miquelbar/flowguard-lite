import { state } from '../../app/state.js';
import * as api from '../../lib/api.js';
import { escapeHtml } from '../../lib/format.js';
import { focusElement } from '../../components/ui/focus.js';
import { loadData } from '../../loaders/viewDataLoader.js';

let modalReturnFocus = null;

export function openPolicyModal({ ip, category }) {
    const modal = document.getElementById("modal-policy");
    if (!modal) return;

    modalReturnFocus = document.activeElement;

    // Reset fields to defaults
    const nameInput = document.getElementById("modal-policy-name");
    const scopeSelect = document.getElementById("modal-policy-scope");
    const targetInput = document.getElementById("modal-policy-target");
    const severitySelect = document.getElementById("modal-policy-severity-threshold");
    const cooldownSelect = document.getElementById("modal-policy-cooldown");
    const quietStartInput = document.getElementById("modal-policy-quiet-hours-start");
    const quietEndInput = document.getElementById("modal-policy-quiet-hours-end");
    const suppressedCheckbox = document.getElementById("modal-policy-suppressed");

    if (nameInput) nameInput.value = "";
    if (scopeSelect) scopeSelect.value = "global";
    if (targetInput) targetInput.value = "";
    if (severitySelect) severitySelect.value = "";
    if (cooldownSelect) cooldownSelect.value = "0";
    if (quietStartInput) quietStartInput.value = "";
    if (quietEndInput) quietEndInput.value = "";
    if (suppressedCheckbox) suppressedCheckbox.checked = true; // Default to silenced

    document.querySelectorAll(".modal-policy-channel-checkbox").forEach(cb => {
        cb.checked = false;
    });

    // Pre-fill fields based on context
    if (ip && category) {
        if (scopeSelect) scopeSelect.value = "ip";
        if (targetInput) targetInput.value = ip;
        if (nameInput) nameInput.value = `Suppress ${category} on ${ip}`;
    } else if (ip) {
        if (scopeSelect) scopeSelect.value = "ip";
        if (targetInput) targetInput.value = ip;
        if (nameInput) nameInput.value = `Suppress ${ip} activity`;
    } else if (category) {
        if (scopeSelect) scopeSelect.value = "alert_type";
        if (targetInput) targetInput.value = category;
        if (nameInput) nameInput.value = `Suppress ${category} alerts`;
    }

    updateModalTargetFieldLabel();
    updateModalPrecedencePreview();

    modal.showModal();
    focusElement("#modal-policy-name");
}

export function closePolicyModal() {
    const modal = document.getElementById("modal-policy");
    if (modal) modal.close();
    if (modalReturnFocus) {
        focusElement(modalReturnFocus);
        modalReturnFocus = null;
    }
}

function updateModalTargetFieldLabel() {
    const scopeSelect = document.getElementById("modal-policy-scope");
    const targetInput = document.getElementById("modal-policy-target");
    const targetLabel = document.getElementById("lbl-modal-policy-target");
    if (!scopeSelect || !targetInput || !targetLabel) return;

    const scope = scopeSelect.value;
    if (scope === "global") {
        targetInput.disabled = true;
        targetInput.value = "";
        targetInput.required = false;
        targetLabel.innerHTML = 'Target <span class="text-muted">(N/A for Global)</span>';
        targetInput.placeholder = "All traffic and alerts";
    } else if (scope === "ip") {
        targetInput.disabled = false;
        targetInput.required = true;
        targetLabel.innerHTML = 'Device IP Address <span class="text-danger">*</span>';
        targetInput.placeholder = "e.g. 192.168.1.50";
    } else if (scope === "subnet") {
        targetInput.disabled = false;
        targetInput.required = true;
        targetLabel.innerHTML = 'Subnet / VLAN CIDR <span class="text-danger">*</span>';
        targetInput.placeholder = "e.g. 192.168.1.0/24";
    } else if (scope === "alert_type") {
        targetInput.disabled = false;
        targetInput.required = true;
        targetLabel.innerHTML = 'Alert Type / Rule Name <span class="text-danger">*</span>';
        targetInput.placeholder = "e.g. port_scan, outbound_volume";
    }
}

function updateModalPrecedencePreview() {
    const previewEl = document.getElementById("modal-policy-precedence-preview");
    if (!previewEl) return;

    const scopeSelect = document.getElementById("modal-policy-scope");
    const targetInput = document.getElementById("modal-policy-target");
    const suppressedCheckbox = document.getElementById("modal-policy-suppressed");
    const severitySelect = document.getElementById("modal-policy-severity-threshold");

    if (!scopeSelect || !targetInput || !suppressedCheckbox || !severitySelect) return;

    const scope = scopeSelect.value;
    const target = targetInput.value.trim();
    const suppressed = suppressedCheckbox.checked;
    const severity = severitySelect.value;

    let previewHtml = "";

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

    let rankText = "";
    let rankColor = "";
    if (scope === "ip") {
        rankText = "IP Scope (Priority 4/4 - Highest)";
        rankColor = "#10b981";
    } else if (scope === "subnet") {
        rankText = "Subnet Scope (Priority 3/4 - High)";
        rankColor = "#38bdf8";
    } else if (scope === "alert_type") {
        rankText = "Alert Type Scope (Priority 2/4 - Medium)";
        rankColor = "#fb923c";
    } else {
        rankText = "Global Scope (Priority 1/4 - Lowest)";
        rankColor = "#94a3b8";
    }
    previewHtml += `<div style="margin-bottom: 0.5rem;"><strong>Precedence Rank:</strong> <span style="color: ${rankColor}; font-weight: 600;">${rankText}</span></div>`;

    let conflicts = [];
    for (const other of state.policiesData || []) {
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
                priorityExplain = `(Identical scopes; first created rule wins)`;
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

    previewEl.innerHTML = previewHtml;
}

export function bindPolicyModalEvents() {
    const scopeSelect = document.getElementById("modal-policy-scope");
    if (scopeSelect) {
        scopeSelect.addEventListener("change", () => {
            updateModalTargetFieldLabel();
            updateModalPrecedencePreview();
        });
    }

    const closeBtn = document.getElementById("btn-close-policy-modal");
    const cancelBtn = document.getElementById("btn-modal-cancel-policy");
    [closeBtn, cancelBtn].forEach(btn => {
        if (btn) {
            btn.addEventListener("click", closePolicyModal);
        }
    });

    const form = document.getElementById("form-modal-policy-editor");
    if (form) {
        form.addEventListener("submit", async (e) => {
            e.preventDefault();

            const nameInput = document.getElementById("modal-policy-name");
            const scopeSelect = document.getElementById("modal-policy-scope");
            const targetInput = document.getElementById("modal-policy-target");
            const severitySelect = document.getElementById("modal-policy-severity-threshold");
            const cooldownSelect = document.getElementById("modal-policy-cooldown");
            const quietStartInput = document.getElementById("modal-policy-quiet-hours-start");
            const quietEndInput = document.getElementById("modal-policy-quiet-hours-end");
            const suppressedCheckbox = document.getElementById("modal-policy-suppressed");

            const name = nameInput ? nameInput.value.trim() : "";
            const scope = scopeSelect ? scopeSelect.value : "global";
            const target = targetInput ? targetInput.value.trim() : "";
            const severityThreshold = severitySelect ? severitySelect.value : "";
            const cooldownSeconds = cooldownSelect ? parseInt(cooldownSelect.value) : 0;
            const quietHoursStart = quietStartInput ? quietStartInput.value.trim() : "";
            const quietHoursEnd = quietEndInput ? quietEndInput.value.trim() : "";
            const suppressed = suppressedCheckbox ? suppressedCheckbox.checked : false;

            const notificationChannels = [];
            document.querySelectorAll(".modal-policy-channel-checkbox").forEach(cb => {
                if (cb.checked) notificationChannels.push(cb.value);
            });

            if (!name) {
                window.showToast("Policy name is required", "error");
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

            if (scope === "alert_type" && !target) {
                window.showToast("Target alert type name is required", "error");
                return;
            }

            if (quietHoursStart && !/^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(quietHoursStart)) {
                window.showToast("Quiet Hours Start must match HH:MM format", "error");
                return;
            }

            if (quietHoursEnd && !/^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(quietHoursEnd)) {
                window.showToast("Quiet Hours End must match HH:MM format", "error");
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

            try {
                await api.savePolicy(payload);
                window.showToast("Suppression policy created successfully");
                closePolicyModal();
                // Reload current view's data
                await loadData(true);
            } catch (err) {
                window.showToast(err.message, "error");
            }
        });
    }

    const inputs = [
        document.getElementById("modal-policy-name"),
        document.getElementById("modal-policy-target"),
        document.getElementById("modal-policy-severity-threshold"),
        document.getElementById("modal-policy-cooldown"),
        document.getElementById("modal-policy-quiet-hours-start"),
        document.getElementById("modal-policy-quiet-hours-end"),
        document.getElementById("modal-policy-suppressed")
    ];

    inputs.forEach(input => {
        if (input) {
            input.addEventListener("input", updateModalPrecedencePreview);
            input.addEventListener("change", updateModalPrecedencePreview);
        }
    });

    document.querySelectorAll(".modal-policy-channel-checkbox").forEach(cb => {
        cb.addEventListener("change", updateModalPrecedencePreview);
    });
}
