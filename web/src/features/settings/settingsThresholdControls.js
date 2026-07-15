import { state } from '../../app/state.js';

export const ANOMALY_TYPE_OPTIONS = [
    ["TRAFFIC_SPIKE", "Traffic spike"],
    ["NEW_DESTINATION", "New destination"],
    ["NEW_PORT", "New port"],
    ["DESTINATION_FANOUT", "Destination fan-out"],
    ["PORT_FANOUT", "Port fan-out"],
    ["BEACONING", "Beaconing"],
    ["NIGHTTIME_TRAFFIC", "Nighttime traffic"],
    ["DEVICE_PROFILE_CHANGE", "Device profile change"],
    ["NEW_INTERNAL_COMMUNICATION", "New internal communication"],
    ["DDOS_HIGH_PPS", "DDoS high PPS"],
    ["DDOS_HIGH_BPS", "DDoS high BPS"],
    ["DDOS_FLOW_FLOOD", "DDoS flow flood"],
    ["DDOS_UDP_FLOOD", "DDoS UDP flood"],
    ["DDOS_ICMP_FLOOD", "DDoS ICMP flood"],
    ["DDOS_TCP_SYN_FLOOD", "DDoS TCP SYN flood"],
    ["SURICATA_ALERT", "Suricata alert"],
    ["UNIFI_SECURITY", "UniFi security"],
    ["UNIFI_CRITICAL", "UniFi critical"]
];

function uniqueStrings(items) {
    const seen = new Set();
    return items
        .map(item => String(item || "").trim())
        .filter(Boolean)
        .filter(item => {
            const key = item.toUpperCase();
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
}

function listValue(id) {
    const el = document.getElementById(id);
    if (!el) return [];
    return uniqueStrings(el.value.split(","));
}

function setListValue(id, values) {
    const el = document.getElementById(id);
    if (el) el.value = uniqueStrings(values).join(", ");
}

function networkOptions() {
    return uniqueStrings([
        ...(state.settingsData?.local_subnets || []),
        ...(state.settingsData?.unifi_syslog_allowed_ips || []),
        ...(state.healthData?.local_networks || [])
    ]);
}

function renderTypePicker(inputId, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const selected = new Set(listValue(inputId).map(item => item.toUpperCase()));
    container.innerHTML = ANOMALY_TYPE_OPTIONS.map(([value, label]) => {
        const active = selected.has(value);
        return `<button type="button" class="selector-chip${active ? " active" : ""}" data-value="${value}" aria-pressed="${active}">${label}<small>${value}</small></button>`;
    }).join("");
}

function renderSubnetPicker(inputId, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const selected = new Set(listValue(inputId));
    const options = networkOptions();
    if (options.length === 0) {
        container.innerHTML = `<p class="text-muted form-help-tiny">No configured local networks yet. Add custom CIDRs below.</p>`;
        return;
    }
    container.innerHTML = options.map(value => {
        const active = selected.has(value);
        return `<button type="button" class="selector-chip selector-chip-network${active ? " active" : ""}" data-value="${value}" aria-pressed="${active}">${value}</button>`;
    }).join("");
}

function renderSelectedList(inputId, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const selected = listValue(inputId);
    if (selected.length === 0) {
        container.innerHTML = `<span class="selector-empty">None selected</span>`;
        return;
    }
    container.innerHTML = selected.map(value => (
        `<span class="selected-chip">${value}<button type="button" aria-label="Remove ${value}" data-value="${value}">×</button></span>`
    )).join("");
}

export function renderThresholdControls() {
    renderTypePicker("setting-disabled-anomaly-types", "setting-disabled-anomaly-types-picker");
    renderTypePicker("setting-notify-suppressed-types", "setting-notify-suppressed-types-picker");
    renderSubnetPicker("setting-muted-anomaly-subnets", "setting-muted-anomaly-subnets-picker");
    renderSubnetPicker("setting-notify-allowed-subnets", "setting-notify-allowed-subnets-picker");
    renderSelectedList("setting-disabled-anomaly-types", "setting-disabled-anomaly-types-selected");
    renderSelectedList("setting-muted-anomaly-subnets", "setting-muted-anomaly-subnets-selected");
    renderSelectedList("setting-notify-allowed-subnets", "setting-notify-allowed-subnets-selected");
    renderSelectedList("setting-notify-suppressed-types", "setting-notify-suppressed-types-selected");
}

export function bindThresholdControlEvents(onChanged) {
    document.querySelectorAll("[data-threshold-picker]").forEach(container => {
        container.addEventListener("click", event => {
            const button = event.target.closest("button[data-value]");
            if (!button) return;
            const inputId = container.dataset.input;
            const value = button.dataset.value;
            const values = listValue(inputId);
            const exists = values.some(item => item.toUpperCase() === value.toUpperCase());
            setListValue(inputId, exists ? values.filter(item => item.toUpperCase() !== value.toUpperCase()) : [...values, value]);
            renderThresholdControls();
            onChanged?.();
        });
    });

    document.querySelectorAll("[data-selected-list]").forEach(container => {
        container.addEventListener("click", event => {
            const button = event.target.closest("button[data-value]");
            if (!button) return;
            const inputId = container.dataset.input;
            const value = button.dataset.value;
            setListValue(inputId, listValue(inputId).filter(item => item.toUpperCase() !== value.toUpperCase()));
            renderThresholdControls();
            onChanged?.();
        });
    });

    document.querySelectorAll("[data-custom-list-input]").forEach(input => {
        input.addEventListener("keydown", event => {
            if (event.key !== "Enter") return;
            event.preventDefault();
            const value = input.value.trim();
            if (!value) return;
            const targetId = input.dataset.target;
            setListValue(targetId, [...listValue(targetId), value]);
            input.value = "";
            renderThresholdControls();
            onChanged?.();
        });
    });
}

