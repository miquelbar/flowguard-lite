const now = Date.parse("2026-07-10T10:00:00.000Z");

const devices = [
    {
        ip: "192.168.30.210",
        hostname: "workstation-210.local",
        label: "Analyst laptop",
        first_seen: "2026-07-08T08:00:00Z",
        last_seen: "2026-07-10T09:55:00Z",
        subnet_vlan: "192.168.30.0/24"
    }
];

const anomalies = [
    {
        id: "alert-1",
        ip: "192.168.30.210",
        type: "BEACONING",
        anomaly_type: "BEACONING",
        severity: "high",
        status: "active",
        description: "Periodic external communication",
        detected_at: "2026-07-10T09:30:00Z",
        reason: "Observed periodic connections.",
        current_value: 6,
        expected_value: 0,
        confidence: 0.91
    }
];

const riskDevices = [
    {
        ip: "192.168.30.210",
        label: "Analyst laptop",
        risk_score: 82,
        risk_level: "high",
        active_alert_count: 1,
        max_severity: "high",
        breakdown: {
            alert_breakdown: [{ severity: "high", count: 1 }]
        }
    }
];

const securitySummary = {
    max_risk_score: 82,
    elevated_risk_devices: 1,
    active_alerts_by_severity: { critical: 0, high: 1, medium: 0, low: 0 },
    risk_distribution: { high: 1, medium: 0, low: 0 },
    detection_enabled: true,
    notification_configured: true,
    top_risk_devices: riskDevices,
    recent_high_alerts: [anomalies[0]]
};

const auditLogs = [
    {
        timestamp: "2026-07-10T09:45:00Z",
        action: "update_settings",
        details: "Settings updated for collectors"
    },
    {
        timestamp: "2026-07-10T09:40:00Z",
        action: "create_policy",
        details: "Created policy named Silence Port Scans"
    }
];

function seriesBuckets(count = 8) {
    return Array.from({ length: count }, (_, idx) => ({
        timestamp: new Date(now - (count - idx) * 60 * 60 * 1000).toISOString(),
        bytes: 1200000 + idx * 150000,
        packets: 5000 + idx * 240,
        flows: 90 + idx * 3
    }));
}

function registerApiStubs() {
    cy.intercept("GET", "/api/auth/status", { authenticated: true, setup_required: false });
    cy.intercept("GET", "/api/settings", {
        first_run_completed: true,
        retention_days: 30,
        port: 8080,
        local_subnets: ["192.168.30.0/24"],
        netflow_port: 2055,
        sflow_port: 6343,
        unifi_syslog_enabled: false,
        unifi_syslog_port: 5514,
        unifi_syslog_allowed_ips: [],
        storage_backend: "sqlite",
        storage_dir: "/data",
        log_level: "info",
        environment: "production",
        ddos_threshold_pps: 5000,
        ddos_threshold_bps: 10000000,
        ddos_threshold_fps: 1000,
        syn_flood_threshold_pps: 1000,
        udp_flood_threshold_pps: 3000,
        icmp_flood_threshold_pps: 500,
        disabled_anomaly_types: [],
        muted_anomaly_subnets: [],
        notify_allowed_subnets: [],
        notify_suppressed_types: [],
        new_destination_min_history_buckets: 12,
        beacon_min_observations: 12,
        beacon_min_interval_seconds: 90,
        traffic_spike_min_packets: 2500,
        traffic_spike_min_bytes: 1048576,
        slack_webhook_url: "",
        webhook_url: "",
        webhook_format: "generic",
        webhook_headers: {},
        telegram_enabled: false,
        telegram_token: "",
        telegram_chat_id: ""
    });
    cy.intercept("GET", "/api/health", { healthy: true, status: "OK", local_ips: ["192.168.30.150"] });
    cy.intercept("GET", "/api/risk/devices", riskDevices);
    cy.intercept("GET", "/api/devices", devices);
    cy.intercept("GET", "/api/anomalies", anomalies);
    cy.intercept("GET", "/api/security/summary", {
        ...securitySummary,
        unifi_configured: true
    });
    cy.intercept("GET", "/api/security/timeline*", [
        { timestamp: "2026-07-10T07:00:00Z", total: 0, critical: 0, high: 0, medium: 0, low: 0 },
        { timestamp: "2026-07-10T09:00:00Z", total: 1, critical: 0, high: 1, medium: 0, low: 0 }
    ]);
    cy.intercept("GET", "/api/stats/protocols*", [
        { key: "TCP", bytes: 1500000 }
    ]);
    cy.intercept("GET", "/api/stats/top-devices*", [
        { key: "192.168.30.210", bytes: 1200000 }
    ]);
    cy.intercept("GET", "/api/stats/heatmap*", [
        { ip: "192.168.30.210", hour: 8, bytes: 300000 }
    ]);
    cy.intercept("GET", "/api/stats/collector-health*", [
        { timestamp: "2026-07-10T09:00:00Z", packets: 100, decode_errors: 0, dropped_packets: 0, queue_depth: 1 }
    ]);
    cy.intercept("GET", "/api/traffic/timeseries*", seriesBuckets());
    cy.intercept("GET", "/api/top/sources*", [
        { key: "192.168.30.210", flows: 42, packets: 8000, bytes: 1500000 }
    ]);
    cy.intercept("GET", "/api/audit-logs*", auditLogs);
    cy.intercept("GET", "/api/traffic/records*", [
        {
            timestamp: "2026-07-10T09:05:00Z",
            collector_kind: "netflow",
            collector_id: "unifi-gateway",
            src_ip: "192.168.30.210",
            dst_ip: "52.84.150.12",
            protocol: 6,
            dst_port: 443,
            flows: 10,
            packets: 2100,
            bytes: 600000
        }
    ]).as("fetchRecords");
    cy.intercept("GET", "/api/policies", []);
    cy.intercept("POST", "/api/policies", { statusCode: 200, body: {} }).as("savePolicy");
    cy.intercept("GET", "/api/notification-rules", []);
    cy.intercept("GET", "/api/devices/192.168.30.210", {
        ip: "192.168.30.210",
        hostname: "workstation-210.local",
        label: "Analyst laptop",
        first_seen: "2026-07-08T08:00:00Z",
        last_seen: "2026-07-10T09:55:00Z",
        subnet_vlan: "192.168.30.0/24",
        baseline: { avg_bytes: 1000000, avg_packets: 4500, avg_flows: 80 },
        risk: riskDevices[0],
        anomalies: [anomalies[0]],
        policies: []
    }).as("fetchDeviceProfile");
    cy.intercept("GET", "/api/devices/192.168.30.210/flows*", seriesBuckets());
    cy.intercept("GET", "/api/devices/192.168.30.210/unifi-events*", []);
}

function visitApp(hash) {
    cy.visit("/" + hash);
    cy.get(".app-shell").should("be.visible");
}

describe("FlowGuard Lite UI click-to-filter workflows", () => {
    beforeEach(() => {
        registerApiStubs();
    });

    it("supports mouse clicking on cells to update filters in Flow Explorer", () => {
        cy.viewport(1440, 900);
        visitApp("#/traffic");

        // Wait for flow records to be loaded
        cy.wait("@fetchRecords");
        cy.get("#tbl-flow-explorer tbody tr").should("have.length", 1);

        // Click IP cell to filter
        cy.get(".clickable-filter.flow-filter-ip").contains("192.168.30.210").click();
        cy.get("#flow-explorer-search").should("have.value", "192.168.30.210 ");
        cy.wait("@fetchRecords");

        // Click Protocol cell to filter
        cy.get(".clickable-filter.flow-filter-protocol").contains("6").click();
        cy.get("#flow-explorer-protocol").should("have.value", "6");
        cy.wait("@fetchRecords");

        // Click Port cell to filter
        cy.get(".clickable-filter.flow-filter-port").contains("443").click();
        cy.get("#flow-explorer-port").should("have.value", "443");
        cy.wait("@fetchRecords");

        // Click Collector cell to filter
        cy.get(".clickable-filter.flow-filter-collector").contains("unifi-gateway").click();
        cy.get("#flow-explorer-collector").should("have.value", "unifi-gateway");
    });

    it("supports keyboard Tab and Enter navigation on cells to update filters", () => {
        cy.viewport(1440, 900);
        visitApp("#/traffic");
        cy.wait("@fetchRecords");

        // Tab into the table and select cell
        cy.get(".clickable-filter.flow-filter-ip").first().focus().type("{enter}");
        cy.get("#flow-explorer-search").should("have.value", "192.168.30.210 ");
        cy.focused().should("have.attr", "data-col", "src-ip");
    });

    it("filters and appends tokens on Alerts list view cells", () => {
        cy.viewport(1440, 900);
        visitApp("#/alerts");

        cy.get("#tbl-anomalies tbody tr").should("have.length", 1);

        // Click IP cell
        cy.get(".clickable-filter.alert-filter-ip").contains("192.168.30.210").click();
        cy.get("#search-anomalies").should("have.value", "192.168.30.210 ");

        // Click Alert Type cell
        cy.get(".clickable-filter.alert-filter-type").contains("BEACONING").click();
        cy.get("#search-anomalies").should("have.value", "192.168.30.210 BEACONING ");
    });

    it("filters on Audit Logs view Action cell badges", () => {
        cy.viewport(1440, 900);
        visitApp("#/audit");

        cy.get("#tbl-audit-logs tbody tr").should("have.length", 2);

        // Click Action cell badge
        cy.get(".clickable-filter.audit-filter-action").contains("update_settings").click();
        cy.get("#search-audit-logs").should("have.value", "update_settings ");
        cy.get("#tbl-audit-logs tbody tr").should("have.length", 1);
    });

    it("opens Policy Modal pre-filled from Device detail and saves successfully", () => {
        cy.viewport(1440, 900);
        visitApp("#/devices");

        cy.contains("#tbl-devices tbody tr", "192.168.30.210").find(".btn-select-device").click();
        cy.wait("@fetchDeviceProfile");

        cy.get("#btn-device-suppress").should("be.visible").click();
        cy.get("#modal-policy").should("have.prop", "open", true);

        // Verify pre-filled inputs
        cy.get("#modal-policy-name").should("have.value", "Suppress 192.168.30.210 activity");
        cy.get("#modal-policy-scope").should("have.value", "ip");
        cy.get("#modal-policy-target").should("have.value", "192.168.30.210");
        cy.get("#modal-policy-suppressed").should("be.checked");

        // Submit form
        cy.get("#form-modal-policy-editor").submit();
        cy.wait("@savePolicy");

        // Verify modal is closed
        cy.get("#modal-policy").should("not.have.prop", "open", true);
    });

    it("opens Policy Modal pre-filled from Alert detail and saves successfully", () => {
        cy.viewport(1440, 900);
        visitApp("#/alerts");

        cy.contains("#tbl-anomalies tbody tr", "192.168.30.210").find(".btn-select-anomaly").click();

        cy.get(".btn-suppress-alert").should("be.visible").click();
        cy.get("#modal-policy").should("have.prop", "open", true);

        // Verify pre-filled inputs
        cy.get("#modal-policy-name").should("have.value", "Suppress BEACONING on 192.168.30.210");
        cy.get("#modal-policy-scope").should("have.value", "ip");
        cy.get("#modal-policy-target").should("have.value", "192.168.30.210");
        cy.get("#modal-policy-suppressed").should("be.checked");

        // Submit form
        cy.get("#form-modal-policy-editor").submit();
        cy.wait("@savePolicy");

        // Verify modal is closed
        cy.get("#modal-policy").should("not.have.prop", "open", true);
    });

    it("verifies Settings Backup and Portability export and validation", () => {
        cy.viewport(1440, 900);
        visitApp("#/settings/backup");

        // Verify elements
        cy.get("#btn-export-backup").should("be.visible");
        cy.get("#input-import-file").should("be.visible");

        // Stub settings saving, deleting and notifications
        cy.intercept("POST", "/api/settings*", { statusCode: 200, body: {} }).as("saveSettings");
        cy.intercept("DELETE", "/api/policies/*", { statusCode: 200, body: {} }).as("deletePolicy");
        cy.intercept("DELETE", "/api/notification-rules/*", { statusCode: 200, body: {} }).as("deleteRule");
        cy.intercept("POST", "/api/notification-rules", { statusCode: 200, body: {} }).as("saveNotificationRule");

        // 1. Upload invalid JSON format
        cy.get("#input-import-file").selectFile({
            contents: Buffer.from("invalid-json"),
            fileName: "backup.json",
            mimeType: "application/json"
        });
        cy.get("#import-preview-summary").should("contain.text", "Error: Invalid JSON structure");
        cy.get("#btn-confirm-import").should("not.be.visible");

        // 2. Upload JSON missing version
        const missingVersion = { settings: {} };
        cy.get("#input-import-file").selectFile({
            contents: Buffer.from(JSON.stringify(missingVersion)),
            fileName: "backup.json",
            mimeType: "application/json"
        });
        cy.get("#import-preview-summary").should("contain.text", "Error: Missing 'version' metadata string");
        cy.get("#btn-confirm-import").should("not.be.visible");

        // 3. Upload JSON with invalid subnet
        const invalidSubnet = {
            version: "1.0",
            settings: {
                port: "8080",
                local_subnets: ["192.168.1.500/24"]
            }
        };
        cy.get("#input-import-file").selectFile({
            contents: Buffer.from(JSON.stringify(invalidSubnet)),
            fileName: "backup.json",
            mimeType: "application/json"
        });
        cy.get("#import-preview-summary").should("contain.text", "Error: Invalid CIDR network address");
        cy.get("#btn-confirm-import").should("not.be.visible");

        // 4. Upload valid backup configuration
        const validBackup = {
            version: "1.0",
            settings: {
                port: "9090", // triggers warning
                local_subnets: ["192.168.1.0/24"],
                netflow_port: 2055,
                sflow_port: 6343,
                unifi_syslog_enabled: false,
                unifi_syslog_port: 5514
            },
            policies: [
                { name: "My policy", scope: "global", target: "", suppressed: true }
            ],
            notification_rules: [
                { name: "Slack rule", scope: "global", target: "", channels: ["slack"] }
            ]
        };

        cy.get("#input-import-file").selectFile({
            contents: Buffer.from(JSON.stringify(validBackup)),
            fileName: "backup.json",
            mimeType: "application/json"
        });

        // Verify preview shows counts
        cy.get("#import-preview-summary").should("contain.text", "Port: 9090");
        cy.get("#import-preview-summary").should("contain.text", "Subnets: 192.168.1.0/24");
        cy.get("#import-preview-summary").should("contain.text", "Policies: 1");
        cy.get("#import-preview-summary").should("contain.text", "Alert Dispatch Rules: 1");

        // Verify warning text matches port and replacement warnings
        cy.get("#import-preview-warning").should("be.visible");
        cy.get("#import-preview-warning").should("contain.text", "Changing web server HTTP port requires a daemon restart");
        cy.get("#import-preview-warning").should("contain.text", "This import will clear all currently active Policies");

        // Click Apply Configuration
        cy.get("#btn-confirm-import").should("be.visible").click();

        // Verify API settings calls
        cy.wait("@saveSettings");
        cy.wait("@savePolicy");
        cy.wait("@saveNotificationRule");

        // Verify navigation redirected (e.g. hash updated to system)
        cy.url().should("include", "#/settings/system");
    });

    it("verifies settings notification channels multiple enable and diagnostic tests", () => {
        cy.viewport(1440, 900);

        // Intercept save notifications settings
        cy.intercept("POST", "/api/settings*", { statusCode: 200, body: {} }).as("saveSettingsNotif");

        // Intercept test-channel endpoint
        cy.intercept("POST", "/api/settings/test-channel", {
            statusCode: 200,
            body: {
                success: true,
                status_code: 200,
                response: "{\"ok\":true,\"description\":\"mock-slack-response\"}"
            }
        }).as("testChannelAPI");

        visitApp("#/settings/notifications");

        // 1. Initially check the checkboxes
        cy.get("#setting-slack-enabled").should("not.be.checked");
        cy.get("#setting-webhook-enabled").should("not.be.checked");
        cy.get("#setting-telegram-enabled-chk").should("not.be.checked");

        // Toggle Slack / Discord
        cy.get("#setting-slack-enabled").check();
        cy.get("#slack-channel-config").should("be.visible");
        cy.get("#setting-slack-webhook-url").clear().type("https://hooks.slack.local/services/T/B/C");

        cy.get("#btn-test-slack").click();
        cy.wait("@testChannelAPI").then((interception) => {
            expect(interception.request.body.channel).to.equal("slack");
            expect(interception.request.body.slack_webhook_url).to.equal("https://hooks.slack.local/services/T/B/C");
        });

        cy.get("#slack-test-console").should("be.visible");
        cy.get("#slack-test-results").should("contain.value", "Success: true");
        cy.get("#slack-test-console .test-status-badge").should("contain.text", "Success");

        // Toggle generic webhook
        cy.get("#setting-webhook-enabled").check();
        cy.get("#webhook-channel-config").should("be.visible");

        // Set webhook generic URL
        cy.get("#setting-webhook-url-generic").clear().type("https://custom-webhook.local/alerts");

        // Click Test Webhook
        cy.get("#btn-test-webhook").click();
        cy.wait("@testChannelAPI").then((interception) => {
            expect(interception.request.body.channel).to.equal("webhook");
            expect(interception.request.body.webhook_url).to.equal("https://custom-webhook.local/alerts");
            expect(interception.request.body.webhook_format).to.equal("generic");
        });

        // Verify diagnostics console
        cy.get("#webhook-test-console").should("be.visible");
        cy.get("#webhook-test-results").should("contain.value", "Success: true");
        cy.get("#webhook-test-results").should("contain.value", "Status Code: 200");
        cy.get("#webhook-test-console .test-status-badge").should("contain.text", "Success");

        // Toggle telegram
        cy.get("#setting-telegram-enabled-chk").check();
        cy.get("#telegram-channel-config").should("be.visible");
        cy.get("#setting-telegram-token").clear().type("123456:fake-token");
        cy.get("#setting-telegram-chat-id").clear().type("-100998877");

        // Intercept test-channel for telegram failure
        cy.intercept("POST", "/api/settings/test-channel", {
            statusCode: 200,
            body: {
                success: false,
                status_code: 400,
                error: "Bad Request: chat not found"
            }
        }).as("testChannelTelegram");

        // Click Test Telegram
        cy.get("#btn-test-telegram").click();
        cy.wait("@testChannelTelegram");

        cy.get("#telegram-test-console").should("be.visible");
        cy.get("#telegram-test-results").should("contain.value", "Success: false");
        cy.get("#telegram-test-results").should("contain.value", "Bad Request: chat not found");
        cy.get("#telegram-test-console .test-status-badge").should("contain.text", "Failure");

        // Submit form
        cy.get("#form-settings-webhook").submit();
        cy.wait("@saveSettingsNotif").then((interception) => {
            const body = interception.request.body;
            expect(body.slack_webhook_url).to.equal("https://hooks.slack.local/services/T/B/C");
            expect(body.webhook_url).to.equal("https://custom-webhook.local/alerts");
            expect(body.webhook_format).to.equal("generic");
            expect(body.telegram_enabled).to.be.true;
            expect(body.telegram_token).to.equal("123456:fake-token");
            expect(body.telegram_chat_id).to.equal("-100998877");
        });
    });

    it("configures detection noise controls with chips and known network selectors", () => {
        cy.viewport(1440, 900);
        cy.intercept("POST", "/api/settings*", { statusCode: 200, body: {} }).as("saveThresholds");

        visitApp("#/settings/thresholds");

        cy.get("#setting-disabled-anomaly-types-picker").contains("button", "New port").click();
        cy.get("#setting-notify-suppressed-types-picker").contains("button", "Beaconing").click();
        cy.get("#setting-muted-anomaly-subnets-picker").contains("button", "192.168.30.0/24").click();
        cy.get("[data-target='setting-notify-allowed-subnets']").type("192.168.40.0/24{enter}");

        cy.get("#setting-disabled-anomaly-types-selected").should("contain.text", "NEW_PORT");
        cy.get("#setting-notify-suppressed-types-selected").should("contain.text", "BEACONING");
        cy.get("#setting-muted-anomaly-subnets-selected").should("contain.text", "192.168.30.0/24");
        cy.get("#setting-notify-allowed-subnets-selected").should("contain.text", "192.168.40.0/24");

        cy.get("#form-settings-thresholds").submit();
        cy.wait("@saveThresholds").then((interception) => {
            const body = interception.request.body;
            expect(body.disabled_anomaly_types).to.deep.equal(["NEW_PORT"]);
            expect(body.notify_suppressed_types).to.deep.equal(["BEACONING"]);
            expect(body.muted_anomaly_subnets).to.deep.equal(["192.168.30.0/24"]);
            expect(body.notify_allowed_subnets).to.deep.equal(["192.168.40.0/24"]);
        });
    });
});
