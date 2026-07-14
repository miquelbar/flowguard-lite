import { state } from '../../app/state.js';
import { renderTableMessage } from '../../components/ui/states.js';
import { escapeHtml } from '../../lib/format.js';

export function renderDevices() {
    const tblDevices = document.getElementById("tbl-devices").querySelector("tbody");
    const inputDeviceSearch = document.getElementById("input-device-search");
    const selectDeviceSubnet = document.getElementById("select-device-subnet");
    if (!tblDevices) return;

    renderDeviceSubnetOptions(selectDeviceSubnet);

    if (state.devicesError) {
        tblDevices.innerHTML = renderTableMessage(4, "error", `Failed to load devices: ${state.devicesError}`);
        return;
    }

    const query = inputDeviceSearch ? inputDeviceSearch.value.trim().toLowerCase() : "";
    const selectedSubnet = state.selectedDeviceSubnet || "";
    const filtered = (state.devicesData || []).filter(dev => {
        const subnet = subnetLabelForDevice(dev.ip);
        const subnetMatch = !selectedSubnet || subnet === selectedSubnet;
        let searchMatch = true;
        if (query !== "") {
            const tokens = query.split(/\s+/);
            searchMatch = tokens.every(token => {
                return dev.ip.toLowerCase().includes(token) ||
                       (dev.hostname && dev.hostname.toLowerCase().includes(token)) ||
                       (dev.label && dev.label.toLowerCase().includes(token));
            });
        }
        return subnetMatch && searchMatch;
    });

    if (filtered.length === 0) {
        tblDevices.innerHTML = renderTableMessage(4, "empty", "No devices match active search filters.");
        return;
    }

    tblDevices.innerHTML = filtered.map(dev => {
        const isSelected = state.selectedDeviceIP === dev.ip;
        return `
            <tr data-ip="${dev.ip}" class="${isSelected ? 'selected' : ''}">
                <td class="font-semibold"><a href="#/devices/${dev.ip}" class="ip-link">${dev.ip}</a></td>
                <td class="text-muted">${dev.hostname || "<i>Unresolved</i>"}</td>
                <td>${dev.label ? `<span class="badge badge-label">${dev.label}</span>` : '<span class="text-muted">-</span>'}</td>
                <td class="text-center">
                    <button class="btn-secondary btn-select-device" data-ip="${dev.ip}" aria-label="Select device ${dev.ip}">Select</button>
                </td>
            </tr>
        `;
    }).join('');

    tblDevices.querySelectorAll("tr").forEach(row => {
        row.addEventListener("click", (e) => {
            if (e.target.tagName === "BUTTON" || e.target.tagName === "A") return;
            const ip = row.getAttribute("data-ip");
            window.location.hash = `#/devices/${ip}`;
        });
    });

    tblDevices.querySelectorAll(".btn-select-device").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const ip = e.target.getAttribute("data-ip");
            window.location.hash = `#/devices/${ip}`;
        });
    });
}

export function subnetLabelForDevice(ip) {
    const parts = String(ip || "").split(".");
    if (parts.length < 3) return "Unknown";
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

export function renderDeviceSubnetOptions(selectEl) {
    if (!selectEl) return;
    const subnets = [...new Set((state.devicesData || []).map(dev => subnetLabelForDevice(dev.ip)))].sort();
    const selected = state.selectedDeviceSubnet || "";
    selectEl.innerHTML = `<option value="">All subnets / VLANs</option>${subnets.map(subnet => `
        <option value="${escapeHtml(subnet)}"${subnet === selected ? " selected" : ""}>${escapeHtml(subnet)}</option>
    `).join("")}`;
}
