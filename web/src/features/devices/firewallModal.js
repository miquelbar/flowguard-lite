import { state } from '../../app/state.js';
import * as api from '../../lib/api.js';
import { focusElement } from '../../components/ui/focus.js';

let modalReturnFocus = null;

export async function openFirewallModal(ip) {
    const modal = document.getElementById("modal-firewall");
    const targetIpField = document.getElementById("firewall-target-ip");
    const codeContent = document.getElementById("firewall-code-content");
    if (!modal) return;
    
    if (targetIpField) targetIpField.value = ip;
    if (codeContent) codeContent.textContent = "Loading rules...";
    state.activeFwTab = "mikrotik";
    
    document.querySelectorAll(".fw-tab-btn").forEach(btn => {
        if (btn.getAttribute("data-fw") === "mikrotik") {
            btn.classList.add("active");
        } else {
            btn.classList.remove("active");
        }
    });

    modalReturnFocus = document.activeElement;
    modal.showModal();
    focusElement("#btn-close-modal");

    try {
        state.firewallTemplates = await api.fetchFirewallTemplates(ip);
        renderFirewallCode();
    } catch (err) {
        if (codeContent) codeContent.textContent = `Error: ${err.message}`;
        window.showToast(err.message, "error");
    }
}



export function renderFirewallCode() {
    const codeContent = document.getElementById("firewall-code-content");
    if (!codeContent || !state.firewallTemplates) return;
    codeContent.textContent = state.firewallTemplates[state.activeFwTab] || "No template configured.";
}

export function restoreFirewallModalFocus() {
    focusElement(modalReturnFocus);
    modalReturnFocus = null;
}

