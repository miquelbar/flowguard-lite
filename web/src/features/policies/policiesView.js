import { state, setSelectedPolicyId, setPolicyRuleEditorDirty } from '../../app/state.js';
import { escapeHtml } from '../../lib/format.js';
import * as api from '../../lib/api.js';
import { renderTableMessage } from '../../components/ui/states.js';
import { bindSplitPaneClose } from '../../components/layout/splitPane.js';
import { focusFirstVisible } from '../../components/ui/focus.js';
import { updatePrecedencePreview, updateTargetFieldLabel } from './policyEditorPreview.js';

export function renderPolicies() {
    const tblPolicies = document.getElementById("tbl-policies").querySelector("tbody");
    if (!tblPolicies) return;

    if (state.policiesError) {
        tblPolicies.innerHTML = renderTableMessage(6, "error", `Failed to load policies: ${state.policiesError}`);
        return;
    }

    if (!state.policiesData || state.policiesData.length === 0) {
        tblPolicies.innerHTML = renderTableMessage(6, "empty", "No policies configured yet.");
        return;
    }

    tblPolicies.innerHTML = state.policiesData.map(p => {
        const isSelected = state.selectedPolicyId === p.id;
        const suppressedText = p.suppressed 
            ? '<span class="badge badge-label text-warning" style="background-color: rgba(245,158,11,0.1); border-color: rgba(245,158,11,0.2);">Silenced</span>' 
            : '<span class="badge badge-label text-success" style="background-color: rgba(16,185,129,0.1); border-color: rgba(16,185,129,0.2);">Active</span>';
        const scopeLabel = p.scope === "alert_type" ? "Alert" : p.scope;
        const scopeBadge = `<span class="badge badge-label" style="background-color: rgba(56,189,248,0.1); border-color: rgba(56,189,248,0.2); color: #38bdf8; text-transform: uppercase;">${scopeLabel}</span>`;
        
        let priorityBadge = "";
        if (p.scope === "ip") {
            priorityBadge = `<span class="policy-priority-badge priority-highest"><span>4</span><small>Highest</small></span>`;
        } else if (p.scope === "subnet") {
            priorityBadge = `<span class="policy-priority-badge priority-high"><span>3</span><small>Subnet</small></span>`;
        } else if (p.scope === "alert_type") {
            priorityBadge = `<span class="policy-priority-badge priority-medium"><span>2</span><small>Alert type</small></span>`;
        } else {
            priorityBadge = `<span class="policy-priority-badge priority-lowest"><span>1</span><small>Lowest</small></span>`;
        }

        return `
            <tr data-id="${p.id}" class="${isSelected ? 'selected' : ''}" style="cursor: pointer;">
                <td class="font-semibold">${escapeHtml(p.name)}</td>
                <td>${scopeBadge}</td>
                <td>${priorityBadge}</td>
                <td class="text-muted font-mono" style="font-size: 0.813rem;">${escapeHtml(p.target || "(all)")}</td>
                <td>${suppressedText}</td>
                <td class="text-center">
                    <button class="btn-secondary btn-select-policy" data-id="${p.id}" aria-label="Select policy ${escapeHtml(p.name)}">Select</button>
                </td>
            </tr>
        `;
    }).join('');

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

export function selectPolicyId(id) {
    if (state.selectedPolicyId !== id && state.policyRuleEditorDirty) {
        if (!confirm("You have unsaved changes in this policy. Discard them?")) {
            // Restore visual selection in nav to match current state
            renderPolicies();
            return;
        }
    }
    setSelectedPolicyId(id);
    setPolicyRuleEditorDirty(false);
    const p = state.policiesData.find(x => x.id === id);
    if (p) {
        selectPolicy(p);
    } else {
        resetPolicyDetails();
    }
    renderPolicies();
}

function selectPolicy(p) {
    const inputPolicyId = document.getElementById("policy-id");
    const inputPolicyName = document.getElementById("policy-name");
    const selectPolicyScope = document.getElementById("policy-scope");
    const inputPolicyTarget = document.getElementById("policy-target");
    const selectPolicySeverityThreshold = document.getElementById("policy-severity-threshold");
    const selectPolicyCooldown = document.getElementById("policy-cooldown");
    const inputPolicyQuietHoursStart = document.getElementById("policy-quiet-hours-start");
    const inputPolicyQuietHoursEnd = document.getElementById("policy-quiet-hours-end");
    const inputPolicySuppressed = document.getElementById("policy-suppressed");
    const btnDelete = document.getElementById("btn-delete-policy");
    const policyDetailsTitle = document.getElementById("policy-details-title");
    const policyDetailsEmpty = document.getElementById("policy-details-empty");
    const policyDetailsContent = document.getElementById("policy-details-content");

    if (inputPolicyId) inputPolicyId.value = p.id;
    if (inputPolicyName) inputPolicyName.value = p.name;
    if (selectPolicyScope) selectPolicyScope.value = p.scope;
    if (inputPolicyTarget) inputPolicyTarget.value = p.target || "";
    if (selectPolicySeverityThreshold) selectPolicySeverityThreshold.value = p.severity_threshold || "";
    if (selectPolicyCooldown) selectPolicyCooldown.value = p.cooldown_seconds || "0";
    if (inputPolicyQuietHoursStart) inputPolicyQuietHoursStart.value = p.quiet_hours_start || "";
    if (inputPolicyQuietHoursEnd) inputPolicyQuietHoursEnd.value = p.quiet_hours_end || "";
    if (inputPolicySuppressed) inputPolicySuppressed.checked = p.suppressed;

    const channels = p.notification_channels || [];
    document.querySelectorAll(".policy-channel-checkbox").forEach(cb => {
        cb.checked = channels.includes(cb.value);
    });

    updateTargetFieldLabel();

    if (btnDelete) btnDelete.classList.remove("hidden");
    if (policyDetailsTitle) policyDetailsTitle.textContent = `Edit Policy: ${p.name}`;
    if (policyDetailsEmpty) policyDetailsEmpty.classList.add("hidden");
    if (policyDetailsContent) policyDetailsContent.classList.remove("hidden");

    updatePrecedencePreview();
    focusFirstVisible(["#policy-name"]);
}

export function startAddPolicy() {
    if (state.policyRuleEditorDirty) {
        if (!confirm("You have unsaved changes in this policy. Discard them?")) {
            return;
        }
    }
    setSelectedPolicyId("new");
    setPolicyRuleEditorDirty(false);
    
    const inputPolicyId = document.getElementById("policy-id");
    const inputPolicyName = document.getElementById("policy-name");
    const selectPolicyScope = document.getElementById("policy-scope");
    const inputPolicyTarget = document.getElementById("policy-target");
    const selectPolicySeverityThreshold = document.getElementById("policy-severity-threshold");
    const selectPolicyCooldown = document.getElementById("policy-cooldown");
    const inputPolicyQuietHoursStart = document.getElementById("policy-quiet-hours-start");
    const inputPolicyQuietHoursEnd = document.getElementById("policy-quiet-hours-end");
    const inputPolicySuppressed = document.getElementById("policy-suppressed");
    const btnDelete = document.getElementById("btn-delete-policy");
    const policyDetailsTitle = document.getElementById("policy-details-title");
    const policyDetailsEmpty = document.getElementById("policy-details-empty");
    const policyDetailsContent = document.getElementById("policy-details-content");

    if (inputPolicyId) inputPolicyId.value = "";
    if (inputPolicyName) inputPolicyName.value = "";
    if (selectPolicyScope) selectPolicyScope.value = "global";
    if (inputPolicyTarget) inputPolicyTarget.value = "";
    if (selectPolicySeverityThreshold) selectPolicySeverityThreshold.value = "";
    if (selectPolicyCooldown) selectPolicyCooldown.value = "0";
    if (inputPolicyQuietHoursStart) inputPolicyQuietHoursStart.value = "";
    if (inputPolicyQuietHoursEnd) inputPolicyQuietHoursEnd.value = "";
    if (inputPolicySuppressed) inputPolicySuppressed.checked = false;

    document.querySelectorAll(".policy-channel-checkbox").forEach(cb => {
        cb.checked = false;
    });

    updateTargetFieldLabel();

    if (btnDelete) btnDelete.classList.add("hidden");
    if (policyDetailsTitle) policyDetailsTitle.textContent = "New Policy";
    if (policyDetailsEmpty) policyDetailsEmpty.classList.add("hidden");
    if (policyDetailsContent) policyDetailsContent.classList.remove("hidden");

    updatePrecedencePreview();
    renderPolicies();
    focusFirstVisible(["#policy-name"]);
}

export function resetPolicyDetails() {
    setSelectedPolicyId(null);
    setPolicyRuleEditorDirty(false);
    const policyDetailsEmpty = document.getElementById("policy-details-empty");
    const policyDetailsContent = document.getElementById("policy-details-content");
    if (policyDetailsEmpty) policyDetailsEmpty.classList.remove("hidden");
    if (policyDetailsContent) policyDetailsContent.classList.add("hidden");
}

export function renderPoliciesView() {
    renderPolicies();
    if (state.selectedPolicyId && state.selectedPolicyId !== "new") {
        selectPolicyId(state.selectedPolicyId);
    } else if (state.selectedPolicyId === "new") {
        startAddPolicy();
    } else {
        resetPolicyDetails();
    }
}

export function bindPoliciesEvents(onReload) {
    const btnAddPolicy = document.getElementById("btn-add-policy");
    if (btnAddPolicy) {
        btnAddPolicy.addEventListener("click", startAddPolicy);
    }

    const btnDeletePolicy = document.getElementById("btn-delete-policy");
    if (btnDeletePolicy) {
        btnDeletePolicy.addEventListener("click", async () => {
            const inputPolicyId = document.getElementById("policy-id");
            if (!inputPolicyId || !inputPolicyId.value) return;
            const id = inputPolicyId.value;

            if (!confirm("Are you sure you want to delete this policy?")) return;

            try {
                await api.deletePolicy(id);
                window.showToast("Policy deleted successfully");
                setSelectedPolicyId(null);
                setPolicyRuleEditorDirty(false);
                resetPolicyDetails();
                if (onReload) await onReload();
            } catch (err) {
                window.showToast(err.message, "error");
            }
        });
    }

    const selectPolicyScope = document.getElementById("policy-scope");
    if (selectPolicyScope) {
        selectPolicyScope.addEventListener("change", () => {
            updateTargetFieldLabel();
            updatePrecedencePreview();
        });
    }

    const formPolicyEditor = document.getElementById("form-policy-editor");
    if (formPolicyEditor) {
        formPolicyEditor.addEventListener("submit", async (e) => {
            e.preventDefault();

            const inputPolicyId = document.getElementById("policy-id");
            const inputPolicyName = document.getElementById("policy-name");
            const selectPolicyScope = document.getElementById("policy-scope");
            const inputPolicyTarget = document.getElementById("policy-target");
            const selectPolicySeverityThreshold = document.getElementById("policy-severity-threshold");
            const selectPolicyCooldown = document.getElementById("policy-cooldown");
            const inputPolicyQuietHoursStart = document.getElementById("policy-quiet-hours-start");
            const inputPolicyQuietHoursEnd = document.getElementById("policy-quiet-hours-end");
            const inputPolicySuppressed = document.getElementById("policy-suppressed");

            const id = inputPolicyId ? inputPolicyId.value : "";
            const name = inputPolicyName ? inputPolicyName.value.trim() : "";
            const scope = selectPolicyScope ? selectPolicyScope.value : "global";
            const target = inputPolicyTarget ? inputPolicyTarget.value.trim() : "";
            const severityThreshold = selectPolicySeverityThreshold ? selectPolicySeverityThreshold.value : "";
            const cooldownSeconds = selectPolicyCooldown ? parseInt(selectPolicyCooldown.value) : 0;
            const quietHoursStart = inputPolicyQuietHoursStart ? inputPolicyQuietHoursStart.value.trim() : "";
            const quietHoursEnd = inputPolicyQuietHoursEnd ? inputPolicyQuietHoursEnd.value.trim() : "";
            const suppressed = inputPolicySuppressed ? inputPolicySuppressed.checked : false;

            const notificationChannels = [];
            document.querySelectorAll(".policy-channel-checkbox").forEach(cb => {
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

            if (id) {
                payload.id = parseInt(id);
            }

            try {
                await api.savePolicy(payload);
                window.showToast(`Policy saved successfully`);
                setPolicyRuleEditorDirty(false);
                if (onReload) await onReload();
            } catch (err) {
                window.showToast(err.message, "error");
            }
        });
    }

    const inputPolicyName = document.getElementById("policy-name");
    const inputPolicyTarget = document.getElementById("policy-target");
    const selectPolicySeverityThreshold = document.getElementById("policy-severity-threshold");
    const selectPolicyCooldown = document.getElementById("policy-cooldown");
    const inputPolicyQuietHoursStart = document.getElementById("policy-quiet-hours-start");
    const inputPolicyQuietHoursEnd = document.getElementById("policy-quiet-hours-end");
    const inputPolicySuppressed = document.getElementById("policy-suppressed");

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
            input.addEventListener("input", () => {
                setPolicyRuleEditorDirty(true);
                updatePrecedencePreview();
            });
            input.addEventListener("change", () => {
                setPolicyRuleEditorDirty(true);
                updatePrecedencePreview();
            });
        }
    });
    document.querySelectorAll(".policy-channel-checkbox").forEach(cb => {
        cb.addEventListener("change", () => {
            setPolicyRuleEditorDirty(true);
            updatePrecedencePreview();
        });
    });

    bindSplitPaneClose(
        ["btn-cancel-policy", "btn-close-policy-details"],
        "#/policies",
        () => {
            resetPolicyDetails();
            renderPolicies();
        },
        ["#btn-add-policy"]
    );
}
