let authMode = "login";

export function currentAuthMode() {
    return authMode;
}

export function showAuthOverlay(mode, message = "") {
    authMode = mode;
    const authOverlay = document.getElementById("auth-overlay");
    const authTitle = document.getElementById("auth-title");
    const authSubtitle = document.getElementById("auth-subtitle");
    const btnAuthSubmit = document.getElementById("btn-auth-submit");
    const authPassword = document.getElementById("auth-password");
    const authMessage = document.getElementById("auth-message");

    if (!authOverlay) return;
    if (authTitle) authTitle.textContent = mode === "setup" ? "Set Admin Password" : "FlowGuard Lite";
    if (authSubtitle) {
        authSubtitle.textContent = mode === "setup"
            ? "Create the local admin password for this FlowGuard node"
            : "Sign in to this FlowGuard node";
    }
    if (btnAuthSubmit) btnAuthSubmit.textContent = mode === "setup" ? "Create Password" : "Sign In";
    if (authPassword) {
        authPassword.value = "";
        authPassword.autocomplete = mode === "setup" ? "new-password" : "current-password";
        authOverlay.classList.remove("hidden");
        authOverlay.setAttribute("aria-hidden", "false");
        authPassword.focus();
    }
    if (authMessage) authMessage.textContent = message;
}

export function hideAuthOverlay() {
    const authOverlay = document.getElementById("auth-overlay");
    if (authOverlay) {
        authOverlay.classList.add("hidden");
        authOverlay.setAttribute("aria-hidden", "true");
    }
}

export function installAuthOverlayGlobal() {
    window.showAuthOverlay = showAuthOverlay;
}
