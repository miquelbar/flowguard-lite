import { state, setSelectedPolicyId, setPolicyRuleEditorDirty } from '../../app/state.js';
import { escapeHtml } from '../../lib/format.js';
import * as api from '../../lib/api.js';
import { renderTableMessage } from '../../components/ui/states.js';
import { bindSplitPaneClose } from '../../components/layout/splitPane.js';
import { focusFirstVisible } from '../../components/ui/focus.js';

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

function updateTargetFieldLabel() {
    const selectPolicyScope = document.getElementById("policy-scope");
    const inputPolicyTarget = document.getElementById("policy-target");
    const labelPolicyTarget = document.getElementById("label-policy-target");
    if (!selectPolicyScope || !inputPolicyTarget || !labelPolicyTarget) return;

    const scope = selectPolicyScope.value;
    if (scope === "global") {
        inputPolicyTarget.disabled = true;
        inputPolicyTarget.value = "";
        inputPolicyTarget.required = false;
        labelPolicyTarget.innerHTML = 'Target <span class="text-muted">(N/A for Global)</span>';
        inputPolicyTarget.placeholder = "All traffic and alerts";
    } else if (scope === "ip") {
        inputPolicyTarget.disabled = false;
        inputPolicyTarget.required = true;
        labelPolicyTarget.innerHTML = 'Device IP Address <span class="text-danger">*</span>';
        inputPolicyTarget.placeholder = "e.g. 192.168.1.50";
    } else if (scope === "subnet") {
        inputPolicyTarget.disabled = false;
        inputPolicyTarget.required = true;
        labelPolicyTarget.innerHTML = 'Subnet / VLAN CIDR <span class="text-danger">*</span>';
        inputPolicyTarget.placeholder = "e.g. 192.168.1.0/24";
    } else if (scope === "alert_type") {
        inputPolicyTarget.disabled = false;
        inputPolicyTarget.required = true;
        labelPolicyTarget.innerHTML = 'Alert Type / Rule Name <span class="text-danger">*</span>';
        inputPolicyTarget.placeholder = "e.g. port_scan, outbound_volume";
    }
}

export function updatePrecedencePreview() {
    const policyPrecedencePreview = document.getElementById("policy-precedence-preview");
    if (!policyPrecedencePreview) return;

    const inputPolicyId = document.getElementById("policy-id");
    const selectPolicyScope = document.getElementById("policy-scope");
    const inputPolicyTarget = document.getElementById("policy-target");
    const inputPolicySuppressed = document.getElementById("policy-suppressed");
    const selectPolicySeverityThreshold = document.getElementById("policy-severity-threshold");

    if (!selectPolicyScope || !inputPolicyTarget || !inputPolicySuppressed || !selectPolicySeverityThreshold) return;

    const scope = selectPolicyScope.value;
    const target = inputPolicyTarget.value.trim();
    const suppressed = inputPolicySuppressed.checked;
    const severity = selectPolicySeverityThreshold.value;

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
    const currentId = inputPolicyId && inputPolicyId.value ? parseInt(inputPolicyId.value) : null;

    for (const other of state.policiesData || []) {
        if (other.id === currentId) continue;
        
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
                priorityExplain = `(Identical scopes; first created rule matches or wins depending on db load order)`;
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

    policyPrecedencePreview.innerHTML = previewHtml;
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
