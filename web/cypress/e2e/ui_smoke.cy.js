const now = Date.parse("2026-07-10T10:00:00.000Z");

const devices = [
    {
        ip: "192.168.30.210",
        hostname: "workstation-210.local",
        label: "Analyst laptop",
        first_seen: "2026-07-08T08:00:00Z",
        last_seen: "2026-07-10T09:55:00Z",
        subnet_vlan: "192.168.30.0/24"
    },
    {
        ip: "192.168.30.42",
        hostname: "nas-42.local",
        label: "NAS",
        first_seen: "2026-07-08T08:00:00Z",
        last_seen: "2026-07-10T09:45:00Z",
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
        reason: "Observed six low-volume periodic connections with bounded jitter.",
        current_value: 6,
        expected_value: 0,
        confidence: 0.91
    },
    {
        id: "alert-2",
        ip: "192.168.30.42",
        type: "NEW_DESTINATION",
        anomaly_type: "NEW_DESTINATION",
        severity: "medium",
        status: "acknowledged",
        description: "New destination contacted",
        detected_at: "2026-07-10T08:45:00Z",
        reason: "Destination was not present in retained baseline."
    }
];

const riskDevices = [
    {
        ip: "192.168.30.210",
        label: "Analyst laptop",
        risk_score: 82,
        risk_level: "high",
        active_alert_count: 2,
        max_severity: "high",
        breakdown: {
            alert_breakdown: [{ severity: "high", count: 1 }, { severity: "medium", count: 1 }]
        }
    }
];

const securitySummary = {
    max_risk_score: 82,
    elevated_risk_devices: 1,
    active_alerts_by_severity: { critical: 0, high: 1, medium: 1, low: 0 },
    risk_distribution: { high: 1, medium: 0, low: 1 },
    detection_enabled: true,
    notification_configured: true,
    top_risk_devices: riskDevices,
    recent_high_alerts: [anomalies[0]]
};

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
        storage_backend: "sqlite",
        storage_dir: "/data",
        log_level: "info",
        environment: "production",
        ddos_threshold_pps: 5000,
        ddos_threshold_bps: 10000000,
        syn_flood_threshold_pps: 1000,
        udp_flood_threshold_pps: 3000,
        icmp_flood_threshold_pps: 500
    });
    cy.intercept("GET", "/api/health", { healthy: true, status: "OK" });
    cy.intercept("GET", "/api/risk/devices", riskDevices);
    cy.intercept("GET", "/api/devices", devices);
    cy.intercept("GET", "/api/devices/192.168.30.210", {
        ...devices[0],
        baseline: { avg_bytes: 1000000, avg_packets: 4500, avg_flows: 80 },
        risk: riskDevices[0],
        anomalies: [anomalies[0]],
        policies: []
    });
    cy.intercept("GET", "/api/devices/192.168.30.210/flows*", seriesBuckets());
    cy.intercept("GET", "/api/devices/52.84.150.12", { statusCode: 404, body: { error: "not found" } }).as("externalDeviceProfile");
    cy.intercept("GET", "/api/anomalies", anomalies);
    cy.intercept("GET", "/api/security/summary", securitySummary);
    cy.intercept("GET", "/api/security/timeline*", [
        { timestamp: "2026-07-10T07:00:00Z", total: 0, critical: 0, high: 0, medium: 0, low: 0 },
        { timestamp: "2026-07-10T08:00:00Z", total: 1, critical: 0, high: 0, medium: 1, low: 0 },
        { timestamp: "2026-07-10T09:00:00Z", total: 2, critical: 0, high: 1, medium: 1, low: 0 }
    ]);
    cy.intercept("GET", "/api/stats/protocols*", [
        { key: "TCP", bytes: 1500000 },
        { key: "UDP", bytes: 500000 }
    ]);
    cy.intercept("GET", "/api/stats/top-devices*", [
        { key: "192.168.30.210", bytes: 1200000 },
        { key: "192.168.30.42", bytes: 800000 }
    ]);
    cy.intercept("GET", "/api/stats/heatmap*", [
        { ip: "192.168.30.210", hour: 8, bytes: 300000 },
        { ip: "192.168.30.42", hour: 9, bytes: 200000 }
    ]);
    cy.intercept("GET", "/api/stats/collector-health*", [
        { timestamp: "2026-07-10T09:00:00Z", packets: 100, decode_errors: 0, dropped_packets: 0, queue_depth: 1 }
    ]);
    cy.intercept("GET", "/api/traffic/timeseries*", seriesBuckets());
    cy.intercept("GET", "/api/top/sources*", [
        { key: "192.168.30.210", flows: 42, packets: 8000, bytes: 1500000 },
        { key: "52.84.150.12", flows: 24, packets: 6000, bytes: 900000 }
    ]);
    cy.intercept("GET", "/api/top/destinations*", [
        { key: "52.84.150.12", flows: 24, packets: 6000, bytes: 900000 }
    ]);
    cy.intercept("GET", "/api/top/ports*", [
        { key: "443", flows: 30, packets: 5000, bytes: 1200000 }
    ]);
    cy.intercept("GET", "/api/traffic/records*", [
        {
            timestamp: "2026-07-10T09:05:00Z",
            src_ip: "192.168.30.210",
            dst_ip: "52.84.150.12",
            protocol: 6,
            dst_port: 443,
            flows: 10,
            packets: 2100,
            bytes: 600000
        },
        {
            timestamp: "2026-07-10T09:00:00Z",
            src_ip: "192.168.30.42",
            dst_ip: "192.168.30.210",
            protocol: 17,
            dst_port: 53,
            flows: 4,
            packets: 400,
            bytes: 80000
        }
    ]);
    cy.intercept("GET", "/api/policies", [
        { id: "policy-1", name: "NAS low noise", scope: "ip", target: "192.168.30.42", action: "silence", min_severity: "low", priority: 1, enabled: true }
    ]);
    cy.intercept("GET", "/api/audit-logs*", [
        { id: "audit-1", timestamp: "2026-07-10T09:30:00Z", actor: "admin", action: "alert.status", target: "alert-1", detail: "acknowledged" }
    ]);
    cy.intercept("GET", "/api/notification-rules", [
        { id: "rule-1", name: "High alerts", enabled: true, severity_min: "high", alert_types: [], scope: "global", target: "", cooldown_seconds: 300, channel_targets: ["webhook"] }
    ]);
    cy.intercept("GET", "/api/notification-logs*", [
        { id: "log-1", timestamp: "2026-07-10T09:20:00Z", rule_name: "High alerts", status: "sent", alert_id: "alert-1" }
    ]);
    cy.intercept({ method: /POST|PUT|DELETE/, url: "/api/**" }, { ok: true });
}

function visitApp(hash) {
    registerApiStubs();
    cy.visit(`/${hash}`);
    cy.get("#auth-overlay").should("have.class", "hidden");
}

describe("FlowGuard Lite UI smoke regressions", () => {
    beforeEach(() => {
        cy.clock(now, ["Date"]);
    });

    it("renders core desktop routes with scoped global time controls", () => {
        cy.viewport(1440, 900);

        [
            ["#/overview", "view-overview", "Threat Posture Summary", true],
            ["#/traffic", "view-dashboard", "Flow Explorer", true],
            ["#/devices", "view-devices", "Device Inventory", false],
            ["#/alerts", "view-anomalies", "Alerts", false],
            ["#/policies", "view-policies", "Traffic Treatment Policies", false],
            ["#/notifications", "view-notifications", "Notification Routing Rules", false],
            ["#/audit", "view-audit", "Audit Log", false],
            ["#/settings/network", "view-settings", "Network Settings", false]
        ].forEach(([hash, viewID, text, shouldShowTimeControls]) => {
            visitApp(hash);
            cy.assertVisibleView(viewID);
            cy.contains(text).should("be.visible");
            cy.assertNoDocumentHorizontalOverflow();
            cy.get(".global-time-control").should(shouldShowTimeControls ? "be.visible" : "not.be.visible");
        });
    });

    it("keeps mobile layout inside the viewport and exposes detail close controls", () => {
        cy.viewport(390, 844);

        visitApp("#/devices");
        cy.assertNoDocumentHorizontalOverflow();
        cy.get("#select-device-subnet").should("contain.text", "192.168.30.0/24");
        cy.contains("#tbl-devices tbody tr", "192.168.30.210").find(".btn-select-device").click();
        cy.location("hash").should("eq", "#/devices/192.168.30.210");
        cy.get("#device-details-content").should("be.visible");
        cy.get("#btn-close-device-details-floating").should("be.visible").click();
        cy.location("hash").should("eq", "#/devices");
        cy.get("#panel-device-details").should("not.be.visible");

        visitApp("#/alerts");
        cy.contains("#tbl-anomalies tbody tr", "192.168.30.210").find(".btn-select-anomaly").click();
        cy.get("#anomaly-details-content").should("be.visible");
        cy.get("#btn-close-anomaly-details").should("be.visible").click();
        cy.get("#panel-anomaly-details").should("not.be.visible");
        cy.location("hash").should("eq", "#/alerts");
        cy.assertNoDocumentHorizontalOverflow();
    });

    it("opens Notifications editor only after user action on mobile", () => {
        cy.viewport(390, 844);
        visitApp("#/notifications");

        cy.get("#notification-details-content").should("not.be.visible");
        cy.contains("Notification Routing Rules").should("be.visible");
        cy.contains("button", "Add Rule").click();
        cy.get("#notification-details-content").should("be.visible");
        cy.get("#notification-rule-name").type("Critical Slack route").should("have.value", "Critical Slack route");
        cy.get("#btn-close-notification-details").should("be.visible").click();
        cy.get("#notification-details-content").should("not.be.visible");
    });

    it("renders only known local device IPs as device links", () => {
        cy.viewport(1440, 900);
        visitApp("#/traffic");

        cy.contains("52.84.150.12").then(($el) => {
            expect($el.closest("a").length, "external IP anchor").to.equal(0);
        });
        cy.contains("192.168.30.210").then(($el) => {
            expect($el.closest("a[href='#/devices/192.168.30.210']").length, "local IP anchor").to.equal(1);
        });
        cy.contains("192.168.30.0/24").should("have.attr", "href", "#/devices/subnet/192.168.30.0%2F24");
    });

    it("keeps retention-aware range buttons and auto-refresh defaults stable", () => {
        cy.viewport(1440, 900);
        visitApp("#/overview");

        cy.get("#select-auto-refresh").should("have.value", "0");
        cy.get("#global-range-tabs").within(() => {
            cy.contains("button", "3d").should("be.visible");
            cy.contains("button", "15d").should("be.visible");
            cy.contains("button", "30d").should("be.visible");
            cy.contains("button", "60d").should("not.exist");
        });
        cy.get("#overview-attack-timeline svg").should("have.attr", "aria-label").and("contain", "hours on X axis");
        cy.get("#overview-subnet-sparklines a[href='#/devices/subnet/192.168.30.0%2F24']").should("exist");
    });

    it("supports sortable tables beyond Flow Explorer", () => {
        cy.viewport(1440, 900);
        visitApp("#/alerts");

        cy.get("#tbl-anomalies thead .sortable-th").should("exist");
        cy.contains("#tbl-anomalies thead .sortable-th", "Severity").click();
        cy.get("#tbl-anomalies tbody tr").first().should("contain.text", "high");
    });
});
