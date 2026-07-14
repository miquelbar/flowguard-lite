import * as api from '../../lib/api.js';

function setConsoleState(consoleId, resultsId, message) {
    const consoleEl = document.getElementById(consoleId);
    const resultsEl = document.getElementById(resultsId);
    const badgeEl = consoleEl?.querySelector(".test-status-badge");

    if (consoleEl) consoleEl.classList.remove("hidden");
    if (resultsEl) resultsEl.value = message;
    if (badgeEl) {
        badgeEl.className = "test-status-badge badge badge-info";
        badgeEl.textContent = "Testing...";
    }

    return { resultsEl, badgeEl };
}

function renderDiagnosticResult(resultsEl, badgeEl, res) {
    if (resultsEl) {
        resultsEl.value = `Success: ${res.success}\nStatus Code: ${res.status_code || "N/A"}\n\nResponse Body:\n${res.response || res.error || "(Empty response)"}`;
    }
    if (!badgeEl) return;
    badgeEl.className = res.success
        ? "test-status-badge badge badge-success"
        : "test-status-badge badge badge-danger";
    badgeEl.textContent = res.success ? "Success" : "Failure";
}

function renderDiagnosticError(resultsEl, badgeEl, err) {
    if (resultsEl) resultsEl.value = `Error: Connection check failed\n\nDetails:\n${err.message}`;
    if (badgeEl) {
        badgeEl.className = "test-status-badge badge badge-danger";
        badgeEl.textContent = "Failure";
    }
}

function collectWebhookHeaders() {
    const headers = {};
    document.querySelectorAll("#webhook-headers-list .webhook-header-row").forEach(row => {
        const key = row.querySelector(".header-key")?.value.trim();
        const val = row.querySelector(".header-value")?.value.trim();
        if (key) headers[key] = val;
    });
    return headers;
}

async function runDiagnostic(consoleId, resultsId, loadingMessage, payloadBuilder) {
    const { resultsEl, badgeEl } = setConsoleState(consoleId, resultsId, loadingMessage);
    try {
        const res = await api.testChannel(payloadBuilder());
        renderDiagnosticResult(resultsEl, badgeEl, res);
    } catch (err) {
        renderDiagnosticError(resultsEl, badgeEl, err);
    }
}

export function bindNotificationDiagnostics() {
    document.getElementById("btn-test-slack")?.addEventListener("click", () => {
        runDiagnostic(
            "slack-test-console",
            "slack-test-results",
            "Sending diagnostic Slack-compatible payload to endpoint...\nWaiting for server response...",
            () => ({
                channel: "slack",
                slack_webhook_url: document.getElementById("setting-slack-webhook-url")?.value.trim() || ""
            })
        );
    });

    document.getElementById("btn-test-webhook")?.addEventListener("click", () => {
        runDiagnostic(
            "webhook-test-console",
            "webhook-test-results",
            "Sending diagnostic webhook payload to endpoint...\nWaiting for server response...",
            () => ({
                channel: "webhook",
                webhook_url: document.getElementById("setting-webhook-url-generic")?.value.trim() || "",
                webhook_format: "generic",
                webhook_headers: collectWebhookHeaders()
            })
        );
    });

    document.getElementById("btn-test-telegram")?.addEventListener("click", () => {
        runDiagnostic(
            "telegram-test-console",
            "telegram-test-results",
            "Sending diagnostic markdown alert via Telegram Bot API...\nWaiting for Telegram confirmation...",
            () => ({
                channel: "telegram",
                telegram_token: document.getElementById("setting-telegram-token")?.value.trim(),
                telegram_chat_id: document.getElementById("setting-telegram-chat-id")?.value.trim()
            })
        );
    });
}
