export function updateStatusIndicator(health) {
    const statusIndicator = document.querySelector(".status-indicator");
    const statusLabel = document.querySelector(".status-label");
    const statusRegion = document.querySelector(".sidebar-footer");
    if (!statusIndicator || !statusLabel) return;

    statusIndicator.className = "status-indicator";
    if (health.healthy || health.status === "OK" || health.status === "healthy") {
        statusIndicator.classList.add("online");
        statusLabel.textContent = "System Healthy";
        if (statusRegion) statusRegion.setAttribute("aria-label", "System status: healthy");
        return;
    }

    statusIndicator.classList.add("offline");
    statusLabel.textContent = health.error_message || "API Offline";
    if (statusRegion) statusRegion.setAttribute("aria-label", `System status: ${statusLabel.textContent}`);
}
