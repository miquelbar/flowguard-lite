// Helper: format bytes into human-readable representation
export function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

// Helper: format numbers with comma grouping
export function formatNumber(num) {
    if (num === undefined || num === null) return "0";
    return num.toLocaleString();
}

// Helper: format date/time string
export function formatTime(isoStr) {
    if (!isoStr) return "-";
    const date = new Date(isoStr);
    return date.toLocaleTimeString() + " " + date.toLocaleDateString();
}

export function formatShortTime(date) {
    if (!date) return "-";
    const d = new Date(date);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function escapeHtml(str) {
    if (!str) return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
