import { markUnsaved } from './settingsSections.js';

export function renderWebhookHeaders(headers) {
    const listContainer = document.getElementById("webhook-headers-list");
    if (!listContainer) return;
    listContainer.innerHTML = "";

    Object.entries(headers).forEach(([key, val]) => {
        appendWebhookHeaderRow(key, val);
    });
}

export function appendWebhookHeaderRow(key = "", val = "") {
    const listContainer = document.getElementById("webhook-headers-list");
    if (!listContainer) return;

    const row = document.createElement("div");
    row.className = "webhook-header-row";
    row.style.display = "flex";
    row.style.gap = "0.5rem";
    row.style.alignItems = "center";

    const keyInput = document.createElement("input");
    keyInput.type = "text";
    keyInput.placeholder = "Header Key";
    keyInput.className = "form-control header-key";
    keyInput.value = key;
    keyInput.style.cssText = "flex: 1; height: 32px; font-size: 0.8rem; padding: 0 0.5rem;";
    keyInput.addEventListener("input", () => markUnsaved("notifications", true));

    const valueInput = document.createElement("input");
    valueInput.type = "text";
    valueInput.placeholder = "Value";
    valueInput.className = "form-control header-value";
    valueInput.value = val;
    valueInput.style.cssText = "flex: 2; height: 32px; font-size: 0.8rem; padding: 0 0.5rem;";
    valueInput.addEventListener("input", () => markUnsaved("notifications", true));

    const removeButton = document.createElement("button");
    removeButton.type = "button";
    removeButton.className = "btn-secondary btn-remove-header";
    removeButton.textContent = "x";
    removeButton.style.cssText = "height: 32px; width: 32px; padding: 0; line-height: 30px; font-size: 1.1rem; text-align: center; border-radius: 6px; cursor: pointer; flex-shrink: 0;";
    removeButton.addEventListener("click", () => {
        row.remove();
        markUnsaved("notifications", true);
    });

    row.append(keyInput, valueInput, removeButton);
    listContainer.appendChild(row);
}

export function syncNotificationFields() {
    const slackEnabled = document.getElementById("setting-slack-enabled")?.checked;
    const slackConfig = document.getElementById("slack-channel-config");
    if (slackConfig) slackConfig.classList.toggle("hidden", !slackEnabled);

    const webhookEnabled = document.getElementById("setting-webhook-enabled")?.checked;
    const webhookConfig = document.getElementById("webhook-channel-config");
    if (webhookConfig) webhookConfig.classList.toggle("hidden", !webhookEnabled);

    const telegramEnabled = document.getElementById("setting-telegram-enabled-chk")?.checked;
    const telegramConfig = document.getElementById("telegram-channel-config");
    if (telegramConfig) telegramConfig.classList.toggle("hidden", !telegramEnabled);
}

export function updateTelegramUrlPreview(token) {
    const preview = document.getElementById("setting-telegram-url-preview");
    if (!preview) return;
    preview.value = token ? `https://api.telegram.org/bot${token}/sendMessage` : "";
}
