export function normalizeBackupConfig(data) {
    const s = data.settings;
    const settings = {
        port: stringField(s.port, "8080"),
        local_subnets: arrayField(s.local_subnets),
        netflow_port: intField(s.netflow_port, 0),
        sflow_port: intField(s.sflow_port, 0),
        unifi_syslog_enabled: Boolean(s.unifi_syslog_enabled),
        unifi_syslog_port: intField(s.unifi_syslog_port, 5514),
        unifi_syslog_allowed_ips: arrayField(s.unifi_syslog_allowed_ips),
        suricata_eve_path: stringField(s.suricata_eve_path),
        capture_interface: stringField(s.capture_interface),
        capture_bpf_filter: stringField(s.capture_bpf_filter, "ip or ip6"),
        capture_promiscuous: Boolean(s.capture_promiscuous),
        storage_dir: stringField(s.storage_dir, "/data"),
        storage_backend: stringField(s.storage_backend, "sqlite"),
        retention_days: intField(s.retention_days, 7),
        disabled_anomaly_types: arrayField(s.disabled_anomaly_types),
        muted_anomaly_subnets: arrayField(s.muted_anomaly_subnets),
        notify_allowed_subnets: arrayField(s.notify_allowed_subnets),
        notify_suppressed_types: arrayField(s.notify_suppressed_types),
        new_destination_min_history_buckets: intField(s.new_destination_min_history_buckets, 12),
        beacon_min_observations: intField(s.beacon_min_observations, 12),
        beacon_min_interval_seconds: intField(s.beacon_min_interval_seconds, 90),
        traffic_spike_min_packets: intField(s.traffic_spike_min_packets, 2500),
        traffic_spike_min_bytes: intField(s.traffic_spike_min_bytes, 1048576),
        ddos_threshold_pps: intField(s.ddos_threshold_pps, 5000),
        ddos_threshold_bps: intField(s.ddos_threshold_bps, 10000000),
        ddos_threshold_fps: intField(s.ddos_threshold_fps, 1000),
        syn_flood_threshold_pps: intField(s.syn_flood_threshold_pps, 1000),
        udp_flood_threshold_pps: intField(s.udp_flood_threshold_pps, 3000),
        icmp_flood_threshold_pps: intField(s.icmp_flood_threshold_pps, 500),
        telegram_enabled: Boolean(s.telegram_enabled),
        telegram_token: stringField(s.telegram_token),
        telegram_chat_id: stringField(s.telegram_chat_id),
        slack_webhook_url: stringField(s.slack_webhook_url),
        webhook_format: stringField(s.webhook_format, "generic"),
        webhook_url: stringField(s.webhook_url),
        webhook_headers: objectStringMap(s.webhook_headers),
        log_level: stringField(s.log_level, "info"),
        environment: stringField(s.environment, "production")
    };

    const error = validateSettings(settings) || validatePolicyList(data.policies) || validateNotificationRules(data.notification_rules);
    if (error) return { error };

    return {
        value: {
            version: stringField(data.version),
            timestamp: stringField(data.timestamp),
            settings,
            policies: (data.policies || []).map(sanitizePolicy),
            notification_rules: (data.notification_rules || []).map(sanitizeNotificationRule)
        }
    };
}

function validateSettings(s) {
    if (!isPort(s.port, 1)) return "Invalid network 'port' value (must be 1-65535).";
    for (const cidr of s.local_subnets) {
        if (!validateCidr(cidr)) return `Invalid CIDR network address in 'local_subnets': '${cidr}'`;
    }
    for (const source of s.unifi_syslog_allowed_ips) {
        if (!validateCidr(source) && !validateIPv4(source)) return `Invalid IP/CIDR in 'unifi_syslog_allowed_ips': '${source}'`;
    }
    if (!isPort(s.netflow_port, 0) || !isPort(s.sflow_port, 0) || !isPort(s.unifi_syslog_port, 0)) return "Collector ports must be between 0 and 65535.";
    if (s.unifi_syslog_enabled && s.unifi_syslog_port === 0) return "UniFi syslog port must be greater than 0 when enabled.";
    if (!["sqlite", "duckdb"].includes(s.storage_backend)) return "Storage backend must be 'sqlite' or 'duckdb'.";
    if (s.retention_days < 1 || s.retention_days > 365) return "Retention days must be between 1 and 365.";
    for (const cidr of [...s.muted_anomaly_subnets, ...s.notify_allowed_subnets]) {
        if (!validateCidr(cidr)) return `Invalid CIDR in detection/noise controls: '${cidr}'`;
    }
    const thresholds = [s.new_destination_min_history_buckets, s.beacon_min_observations, s.beacon_min_interval_seconds, s.traffic_spike_min_packets, s.traffic_spike_min_bytes, s.ddos_threshold_pps, s.ddos_threshold_bps, s.ddos_threshold_fps, s.syn_flood_threshold_pps, s.udp_flood_threshold_pps, s.icmp_flood_threshold_pps];
    if (thresholds.some(v => !Number.isInteger(v) || v < 1)) return "Detection thresholds must be positive integers.";
    if (!["slack", "generic"].includes(s.webhook_format)) return "Webhook format must be 'slack' or 'generic'.";
    if (s.slack_webhook_url && !/^https?:\/\//i.test(s.slack_webhook_url)) return "Slack Webhook URL must be HTTP or HTTPS.";
    if (s.webhook_url && !/^https?:\/\//i.test(s.webhook_url)) return "Webhook URL must be HTTP or HTTPS.";
    if (!["debug", "info", "warn", "error"].includes(s.log_level)) return "Log level must be debug, info, warn, or error.";
    if (!["production", "development"].includes(s.environment)) return "Environment must be production or development.";
    return "";
}

function validatePolicyList(policies) {
    if (policies !== undefined && !Array.isArray(policies)) return "'policies' must be an array.";
    for (const p of policies || []) {
        if (typeof p !== "object" || p === null || !p.name || !p.scope || p.target === undefined) return "Invalid policy object in policies list (must contain 'name', 'scope', and 'target').";
        if (!["global", "ip", "subnet", "alert_type"].includes(p.scope)) return `Invalid policy scope '${p.scope}' in policy '${p.name}'.`;
    }
    return "";
}

function validateNotificationRules(rules) {
    if (rules !== undefined && !Array.isArray(rules)) return "'notification_rules' must be an array.";
    for (const r of rules || []) {
        if (typeof r !== "object" || r === null || !r.name || !r.scope || !Array.isArray(r.channels)) return "Invalid rule in notification rules list (must contain 'name', 'scope', and 'channels' array).";
    }
    return "";
}

function sanitizePolicy(p) {
    return {
        name: stringField(p.name),
        scope: stringField(p.scope),
        target: stringField(p.target),
        severity_threshold: stringField(p.severity_threshold),
        cooldown_seconds: intField(p.cooldown_seconds, 0),
        quiet_hours_start: stringField(p.quiet_hours_start),
        quiet_hours_end: stringField(p.quiet_hours_end),
        suppressed: Boolean(p.suppressed),
        notification_channels: arrayField(p.notification_channels)
    };
}

function sanitizeNotificationRule(r) {
    return {
        name: stringField(r.name),
        scope: stringField(r.scope),
        target: stringField(r.target),
        channels: arrayField(r.channels)
    };
}

function stringField(value, fallback = "") {
    return typeof value === "string" ? value.trim() : fallback;
}

function intField(value, fallback) {
    const num = Number(value);
    return Number.isInteger(num) ? num : fallback;
}

function arrayField(value) {
    return Array.isArray(value) ? value.filter(item => typeof item === "string").map(item => item.trim()).filter(Boolean) : [];
}

function objectStringMap(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
    return Object.fromEntries(Object.entries(value).filter(([k, v]) => typeof k === "string" && typeof v === "string"));
}

function isPort(value, min) {
    const port = typeof value === "string" ? parseInt(value, 10) : value;
    return Number.isInteger(port) && port >= min && port <= 65535;
}

function validateIPv4(ip) {
    if (typeof ip !== "string") return false;
    const octets = ip.split(".");
    if (octets.length !== 4) return false;
    return octets.every(octetStr => {
        const octet = parseInt(octetStr, 10);
        return !isNaN(octet) && octet >= 0 && octet <= 255 && String(octet) === octetStr;
    });
}

function validateCidr(cidr) {
    if (typeof cidr !== "string") return false;
    const parts = cidr.split("/");
    if (parts.length !== 2) return false;
    const mask = parseInt(parts[1], 10);
    return validateIPv4(parts[0]) && !isNaN(mask) && mask >= 0 && mask <= 32 && String(mask) === parts[1];
}
