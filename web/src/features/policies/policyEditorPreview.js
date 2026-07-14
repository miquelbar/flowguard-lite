import { state } from '../../app/state.js';
import { escapeHtml } from '../../lib/format.js';

export function updateTargetFieldLabel() {
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

    let previewHtml = `${scopeBehavior(scope, target)}${policyAction(suppressed, severity)}${rankSummary(scope)}`;
    const conflicts = policyConflicts(inputPolicyId, scope, target);
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

function scopeBehavior(scope, target) {
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
    return `<div style="margin-bottom: 0.5rem;">${behavior}</div>`;
}

function policyAction(suppressed, severity) {
    let actionExplain = suppressed ? "Silences matching alerts completely (suppresses all notifications)." : "Keeps matching alerts active.";
    if (!suppressed) {
        if (severity === "low") actionExplain += " Alert on Low and above (all alerts).";
        else if (severity === "medium") actionExplain += " Alert only on Medium and High (Low alerts will be silenced).";
        else if (severity === "high") actionExplain += " Alert only on High (Low and Medium alerts will be silenced).";
        else actionExplain += " Alert on all severities (no minimum threshold).";
    }
    return `<div style="margin-bottom: 0.5rem; border-left: 2px solid var(--accent-color); padding-left: 0.5rem; font-style: italic; color: var(--text-secondary);">${actionExplain}</div>`;
}

function rankSummary(scope) {
    const ranks = {
        ip: ["IP Scope (Priority 4/4 - Highest)", "#10b981"],
        subnet: ["Subnet Scope (Priority 3/4 - High)", "#38bdf8"],
        alert_type: ["Alert Type Scope (Priority 2/4 - Medium)", "#fb923c"],
        global: ["Global Scope (Priority 1/4 - Lowest)", "#94a3b8"]
    };
    const [rankText, rankColor] = ranks[scope] || ranks.global;
    return `<div style="margin-bottom: 0.5rem;"><strong>Precedence Rank:</strong> <span style="color: ${rankColor}; font-weight: 600;">${rankText}</span></div>`;
}

function policyConflicts(inputPolicyId, scope, target) {
    const currentId = inputPolicyId && inputPolicyId.value ? parseInt(inputPolicyId.value) : null;
    const scopePriority = { ip: 4, subnet: 3, alert_type: 2, global: 1 };

    return (state.policiesData || []).filter(other => other.id !== currentId && policiesOverlap(scope, target, other)).map(other => {
        const myP = scopePriority[scope] || 0;
        const otherP = scopePriority[other.scope] || 0;
        let priorityExplain = `(Identical scopes; first created rule matches or wins depending on db load order)`;
        if (myP > otherP) priorityExplain = `(This policy overrides "${escapeHtml(other.name)}")`;
        else if (myP < otherP) priorityExplain = `(This policy is overridden by "${escapeHtml(other.name)}")`;
        return `<li>Overlaps with <strong>${escapeHtml(other.name)}</strong> [${other.scope}] - <span style="font-style: italic;">${priorityExplain}</span></li>`;
    });
}

function policiesOverlap(scope, target, other) {
    if (scope === "global" && other.scope === "global") return true;
    if (scope === "ip" && other.scope === "ip" && target === other.target && target !== "") return true;
    if (scope === "subnet" && other.scope === "subnet" && target === other.target && target !== "") return true;
    if (scope === "alert_type" && other.scope === "alert_type" && target === other.target && target !== "") return true;
    return scope === "ip" && other.scope === "subnet" && target !== "" && other.target !== "";
}
