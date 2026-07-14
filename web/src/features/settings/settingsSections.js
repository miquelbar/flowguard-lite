import { state, setActiveSettingsSection, setUnsavedChanges } from '../../app/state.js';

let activeSettingsSection = "access";

export function syncActiveSettingsSectionFromState() {
    activeSettingsSection = normalizeSettingsSection(state.activeSettingsSection);
    return activeSettingsSection;
}

export function normalizeSettingsSection(section) {
    const allowed = new Set(["access", "network", "collectors", "storage", "thresholds", "notifications", "integrations", "system"]);
    return allowed.has(section) ? section : "access";
}

export function getSettingsSectionLabel(sec) {
    const labels = {
        access: "Access Control",
        network: "Network Settings",
        collectors: "Collectors Setup",
        storage: "Storage & Retention",
        thresholds: "Detection Thresholds",
        notifications: "Notifications & Routing",
        integrations: "Router Integrations",
        system: "System Settings"
    };
    return labels[sec] || sec;
}

export function updateSettingsNavActive(sec) {
    document.querySelectorAll(".settings-nav .settings-nav-link").forEach(link => {
        if (link.getAttribute("data-section") === sec) {
            link.classList.add("active");
        } else {
            link.classList.remove("active");
        }
    });
}

export function switchSettingsSection(section, options = {}) {
    const opts = { confirmUnsaved: true, updateHash: true, ...options };
    section = normalizeSettingsSection(section);
    if (section !== activeSettingsSection && opts.confirmUnsaved && state.unsavedChanges[activeSettingsSection]) {
        if (!confirm(`You have unsaved changes in the ${getSettingsSectionLabel(activeSettingsSection)} section. Do you want to discard them?`)) {
            updateSettingsNavActive(activeSettingsSection);
            return;
        }
        markUnsaved(activeSettingsSection, false);
    }

    activeSettingsSection = section;
    setActiveSettingsSection(section);

    document.querySelectorAll(".settings-main .settings-card").forEach(card => {
        const id = card.getAttribute("id");
        if (id === `settings-${section}`) {
            card.classList.remove("hidden");
        } else {
            card.classList.add("hidden");
        }
    });

    updateSettingsNavActive(section);
    if (opts.updateHash) {
        const nextHash = `#/settings/${section}`;
        if (window.location.hash !== nextHash) {
            window.location.hash = nextHash;
        }
    }
}

export function markUnsaved(section, isUnsaved) {
    setUnsavedChanges(section, isUnsaved);
    const card = document.getElementById(`settings-${section}`);
    if (!card) return;
    
    let badge = card.querySelector(".unsaved-badge");
    if (isUnsaved) {
        if (!badge) {
            badge = document.createElement("span");
            badge.className = "badge badge-warning unsaved-badge";
            badge.style.marginLeft = "0.5rem";
            badge.style.fontSize = "0.7rem";
            badge.style.background = "#fb923c";
            badge.style.color = "#fff";
            badge.style.borderRadius = "4px";
            badge.style.padding = "0.1rem 0.3rem";
            badge.textContent = "Unsaved Changes";
            const h3 = card.querySelector(".settings-card-header h3");
            if (h3) h3.appendChild(badge);
        }
        const navLink = document.querySelector(`.settings-nav a[data-section="${section}"]`);
        if (navLink && !navLink.querySelector(".unsaved-dot")) {
            const dot = document.createElement("span");
            dot.className = "unsaved-dot";
            dot.style.display = "inline-block";
            dot.style.width = "6px";
            dot.style.height = "6px";
            dot.style.background = "#fb923c";
            dot.style.borderRadius = "50%";
            dot.style.marginLeft = "0.5rem";
            navLink.appendChild(dot);
        }
    } else {
        if (badge) badge.remove();
        const navLink = document.querySelector(`.settings-nav a[data-section="${section}"]`);
        if (navLink) {
            const dot = navLink.querySelector(".unsaved-dot");
            if (dot) dot.remove();
        }
    }
}
