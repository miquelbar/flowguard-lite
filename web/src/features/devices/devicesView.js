import { state } from '../../app/state.js';
import * as api from '../../lib/api.js';
import { renderDevices } from './devicesList.js';
import { selectDevice, showNoDeviceSelected } from './deviceDetail.js';
import { renderFirewallCode, restoreFirewallModalFocus } from './firewallModal.js';
import { focusFirstVisible } from '../../components/ui/focus.js';

export function renderDevicesView() {
    renderDevices();
    if (state.selectedDeviceIP) {
        selectDevice(state.selectedDeviceIP);
    } else {
        showNoDeviceSelected();
    }
}

export function bindDevicesEvents() {
    const inputDeviceSearch = document.getElementById("input-device-search");
    if (inputDeviceSearch) {
        inputDeviceSearch.addEventListener("input", () => {
            renderDevices();
        });
    }
    const selectDeviceSubnet = document.getElementById("select-device-subnet");
    if (selectDeviceSubnet) {
        selectDeviceSubnet.addEventListener("change", (e) => {
            const subnet = e.target.value;
            state.selectedDeviceSubnet = subnet;
            state.selectedDeviceIP = null;
            window.location.hash = subnet ? `#/devices/subnet/${encodeURIComponent(subnet)}` : "#/devices";
        });
    }

    const formUpdateLabel = document.getElementById("form-update-label");
    const inputDetailLabel = document.getElementById("input-detail-label");
    if (formUpdateLabel && inputDetailLabel) {
        formUpdateLabel.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!state.selectedDeviceIP) return;

            const newLabel = inputDetailLabel.value.trim();
            try {
                await api.updateDeviceLabel(state.selectedDeviceIP, newLabel);
                window.showToast(`Label updated for ${state.selectedDeviceIP}.`);
                state.devicesData = await api.fetchDevices();
                selectDevice(state.selectedDeviceIP);
            } catch (err) {
                window.showToast(err.message, "error");
            }
        });
    }

    const btnCloseModal = document.getElementById("btn-close-modal");
    if (btnCloseModal) {
        btnCloseModal.addEventListener("click", () => {
            const modal = document.getElementById("modal-firewall");
            if (modal) modal.close();
            restoreFirewallModalFocus();
        });
    }

    const btnCopyRules = document.getElementById("btn-copy-rules");
    if (btnCopyRules) {
        btnCopyRules.addEventListener("click", () => {
            const codeContent = document.getElementById("firewall-code-content");
            if (codeContent) {
                const code = codeContent.textContent;
                navigator.clipboard.writeText(code).then(() => {
                    window.showToast("Rules copied.");
                }).catch(err => {
                    window.showToast("Copy failed: " + err, "error");
                });
            }
        });
    }

    document.querySelectorAll(".fw-tab-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            document.querySelectorAll(".fw-tab-btn").forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            state.activeFwTab = e.target.getAttribute("data-fw");
            renderFirewallCode();
        });
    });

    const btnCloseDetails = document.getElementById("btn-close-device-details");
    const btnCloseDetailsFloating = document.getElementById("btn-close-device-details-floating");
    [btnCloseDetails, btnCloseDetailsFloating].forEach(btn => {
        if (!btn) return;
        btn.addEventListener("click", () => {
            window.location.hash = "#/devices";
            focusFirstVisible(["#input-device-search", "#select-device-subnet"]);
        });
    });
}
