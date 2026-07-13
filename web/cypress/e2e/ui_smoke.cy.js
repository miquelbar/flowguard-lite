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
    cy.intercept("GET", "/api/devices/192.168.30.210/unifi-events*", [
        {
            id: 1,
            timestamp: "2026-07-10T09:40:00Z",
            source_gateway: "192.168.30.1",
            category: "Security Detections",
            severity: "high",
            client_ip: "192.168.30.210",
            summary: "IDS Alert: Trojan detected",
            attributes: { signature_id: "2018402" }
        }
    ]);
    cy.intercept("GET", "/api/security/unifi-events*", [
        {
            id: 1,
            timestamp: "2026-07-10T09:40:00Z",
            source_gateway: "192.168.30.1",
            category: "Security Detections",
            severity: "high",
            client_ip: "192.168.30.210",
            summary: "IDS Alert: Trojan detected",
            attributes: { signature_id: "2018402" }
        }
    ]);
    cy.intercept("GET", "/api/devices/52.84.150.12", { statusCode: 404, body: { error: "not found" } }).as("externalDeviceProfile");
    cy.intercept("GET", "/api/anomalies", anomalies);
    cy.intercept("GET", "/api/security/summary", {
        ...securitySummary,
        unifi_configured: true
    });
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
            collector_kind: "netflow",
            collector_id: "unifi-gateway",
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
            collector_kind: "pcap",
            collector_id: "pcap:br0",
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
        { id: 1, name: "NAS low noise", scope: "ip", target: "192.168.30.42", action: "silence", min_severity: "low", priority: 1, enabled: true }
    ]);
    cy.intercept("GET", "/api/audit-logs*", [
        { id: "audit-1", timestamp: "2026-07-10T09:30:00Z", actor: "admin", action: "alert.status", target: "alert-1", detail: "acknowledged" }
    ]);
    cy.intercept("GET", "/api/notification-rules", [
        { id: 1, name: "High alerts", enabled: true, severity_min: "high", alert_types: [], scope: "global", target: "", cooldown_seconds: 300, channel_targets: ["webhook"] }
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

function visitUnauthenticatedApp() {
    registerApiStubs();
    cy.intercept("GET", "/api/auth/status", { authenticated: false, setup_required: false });
    cy.visit("/");
}

function expectedDomainStart(durationMs) {
    return new Date(now - durationMs).toISOString();
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
        cy.get("#device-details-content").should("exist").and("not.have.class", "hidden");
        cy.get("#btn-close-device-details-floating").should("be.visible").click();
        cy.location("hash").should("eq", "#/devices");
        cy.get("#panel-device-details").should("not.be.visible");

        visitApp("#/alerts");
        cy.contains("#tbl-anomalies tbody tr", "192.168.30.210").find(".btn-select-anomaly").click();
        cy.get("#anomaly-details-content").should("be.visible");
        cy.get("#btn-close-anomaly-details-floating").should("be.visible").click();
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

    it("uses the selected time range as chart x-axis domains", () => {
        cy.viewport(1440, 900);
        const dayMs = 24 * 60 * 60 * 1000;

        visitApp("#/overview");
        cy.get("#overview-attack-timeline svg")
            .should("have.attr", "data-x-domain", "selected-range")
            .and("have.attr", "data-domain-start", expectedDomainStart(dayMs))
            .and("have.attr", "data-domain-end", new Date(now).toISOString());

        visitApp("#/traffic");
        cy.get("#traffic-chart-bytes")
            .should("have.attr", "data-x-domain", "selected-range")
            .and("have.attr", "data-domain-start", expectedDomainStart(dayMs))
            .and("have.attr", "data-domain-end", new Date(now).toISOString());
        cy.get("#traffic-chart-packets")
            .should("have.attr", "data-x-domain", "selected-range")
            .and("have.attr", "data-domain-start", expectedDomainStart(dayMs));
    });

    it("supports sortable tables beyond Flow Explorer", () => {
        cy.viewport(1440, 900);
        visitApp("#/alerts");

        cy.get("#tbl-anomalies thead .sortable-th").should("exist");
        cy.contains("#tbl-anomalies thead .sortable-th", "Severity").click();
        cy.get("#tbl-anomalies tbody tr").first().should("contain.text", "high");
    });

    it("focuses the auth overlay password field when login is required", () => {
        visitUnauthenticatedApp();
        cy.get("#auth-overlay")
            .should("not.have.class", "hidden")
            .and("have.attr", "role", "dialog")
            .and("have.attr", "aria-hidden", "false");
        cy.focused().should("have.id", "auth-password");
    });

    it("keeps critical controls named and keyboard reachable", () => {
        cy.viewport(1440, 900);

        visitApp("#/overview");
        cy.get("#btn-toggle-sidebar")
            .should("have.attr", "aria-label", "Collapse sidebar")
            .focus()
            .type("{enter}")
            .should("have.attr", "aria-expanded", "false");
        cy.get("#nav-dashboard").should("have.attr", "aria-label", "Open Traffic").focus().type("{enter}");
        cy.location("hash").should("eq", "#/traffic");

        cy.get(".global-range-btn[data-range='6h']")
            .should("have.attr", "aria-label")
            .and("contain", "6h");
        cy.get(".global-range-btn[data-range='6h']").focus().type("{enter}");
        cy.get(".global-range-btn[data-range='6h']").should("have.attr", "aria-pressed", "true");
        cy.get(".global-range-btn[data-range='24h']").should("have.attr", "aria-pressed", "false");

        cy.get("#tbl-flow-explorer [data-flow-sort='bytes']")
            .should("have.attr", "aria-label")
            .and("match", /bytes/i);
        cy.get("#tbl-flow-explorer [data-flow-sort='bytes']").focus().type("{enter}");
        cy.get("#tbl-flow-explorer [data-flow-sort='bytes']").closest("th").should("have.attr", "aria-sort", "descending");
    });

    it("keeps layout primitives bounded on desktop and mobile", () => {
        cy.viewport(1440, 900);
        visitApp("#/devices");

        cy.assertNoDocumentHorizontalOverflow();
        cy.assertElementDoesNotWidenDocument(".app-shell");
        cy.get(".device-split-layout").should(($layout) => {
            const style = getComputedStyle($layout[0]);
            expect(style.display, "desktop split layout display").to.equal("grid");
            expect(style.gridTemplateColumns, "desktop split columns").to.match(/\d+(\.\d+)?px \d+(\.\d+)?px/);
        });
        cy.get("#panel-device-details").should(($panel) => {
            expect(getComputedStyle($panel[0]).position, "desktop detail position").to.equal("static");
        });
        cy.get("#tbl-devices").parents(".table-container").first().should(($container) => {
            expect(getComputedStyle($container[0]).overflowX, "table overflow x").to.match(/auto|scroll/);
        });

        cy.viewport(390, 844);
        visitApp("#/traffic");

        cy.assertNoDocumentHorizontalOverflow();
        cy.assertElementDoesNotWidenDocument(".app-shell");
        cy.get(".sidebar .nav-links").should(($nav) => {
            expect(getComputedStyle($nav[0]).overflowX, "mobile nav local overflow").to.equal("auto");
        });
        cy.get("#global-range-tabs").should(($tabs) => {
            expect(getComputedStyle($tabs[0]).overflowX, "range tabs local overflow").to.equal("auto");
        });
        cy.get("#tbl-flow-explorer").parents(".table-container").first().should(($container) => {
            expect(getComputedStyle($container[0]).overflowX, "flow table local overflow").to.match(/auto|scroll/);
        });

        visitApp("#/devices");
        cy.contains("#tbl-devices tbody tr", "192.168.30.210").find(".btn-select-device").click();
        cy.get("#panel-device-details").should(($panel) => {
            const style = getComputedStyle($panel[0]);
            expect(style.position, "mobile detail overlay position").to.equal("fixed");
            expect(style.display, "mobile detail overlay display").to.equal("flex");
        });
        cy.assertNoDocumentHorizontalOverflow();
    });

    it("manages focus for mobile detail overlays and firewall dialog", () => {
        cy.viewport(390, 844);
        visitApp("#/devices");

        cy.contains("#tbl-devices tbody tr", "192.168.30.210").find(".btn-select-device").click();
        cy.location("hash").should("eq", "#/devices/192.168.30.210");
        cy.get("#device-details-content").should("exist").and("not.have.class", "hidden");
        cy.focused().should("have.id", "btn-close-device-details-floating");
        cy.get("#btn-close-device-details-floating").type("{enter}");
        cy.location("hash").should("eq", "#/devices");
        cy.focused().should("have.id", "input-device-search");

        cy.viewport(1440, 900);
        visitApp("#/devices/192.168.30.210");
        cy.get("#device-details-content").should("exist").and("not.have.class", "hidden");
        cy.get("#btn-device-fw-rules")
            .should("have.attr", "aria-label")
            .and("contain", "192.168.30.210");
        cy.get("#btn-device-fw-rules").focus().type("{enter}");
        cy.get("#modal-firewall").should("have.prop", "open", true);
        cy.focused().should("have.id", "btn-close-modal");
        cy.get("#btn-close-modal").type("{enter}");
        cy.get("#modal-firewall").should("not.have.prop", "open", true);
        cy.focused().should("have.id", "btn-device-fw-rules");
    });

    it("handles dirty form protection and navigation intercepts", () => {
        cy.viewport(1440, 900);

        // 1. Policies view dirty form confirmation
        visitApp("#/policies");
        cy.contains("button", "Add Policy").click();
        cy.get("#policy-name").type("My Custom Rule");

        // Stub confirm to return false (Cancel)
        cy.window().then((win) => {
            cy.stub(win, "confirm").as("confirmStub").returns(false);
        });

        // Click first policy in table (should reject and stay)
        cy.contains("#tbl-policies tbody tr", "NAS low noise").click();
        cy.get("@confirmStub").should("have.been.calledWith", "You have unsaved changes in this policy. Discard them?");
        cy.get("#policy-name").should("have.value", "My Custom Rule");

        // Stub confirm to return true (OK)
        cy.window().then((win) => {
            if (win.confirm.restore) win.confirm.restore();
            cy.stub(win, "confirm").as("confirmStubOk").returns(true);
        });

        // Click first policy in table (should accept and load "NAS low noise")
        cy.contains("#tbl-policies tbody tr", "NAS low noise").click();
        cy.get("@confirmStubOk").should("have.been.calledWith", "You have unsaved changes in this policy. Discard them?");
        cy.get("#policy-name").should("have.value", "NAS low noise");

        // 2. View transition intercept
        cy.get("#policy-name").clear().type("Dirty policy form");

        // Stub confirm to return false (Cancel)
        cy.window().then((win) => {
            if (win.confirm.restore) win.confirm.restore();
            cy.stub(win, "confirm").as("confirmStubCancelNav").returns(false);
        });

        // Try to click sidebar link for Traffic (should reject and stay)
        cy.get("#nav-dashboard").click();
        cy.get("@confirmStubCancelNav").should("have.been.calledWith", "You have unsaved changes. Are you sure you want to discard them?");
        cy.location("hash").should("eq", "#/policies");

        // Stub confirm to return true (OK)
        cy.window().then((win) => {
            if (win.confirm.restore) win.confirm.restore();
            cy.stub(win, "confirm").as("confirmStubOkNav").returns(true);
        });

        // Try to click sidebar link for Traffic (should accept and navigate)
        cy.get("#nav-dashboard").click();
        cy.get("@confirmStubOkNav").should("have.been.calledWith", "You have unsaved changes. Are you sure you want to discard them?");
        cy.location("hash").should("eq", "#/traffic");
    });

    it("verifies UniFi SIEM events, collector attribution, and settings controls", () => {
        cy.viewport(1440, 900);

        // 1. Verify Overview detection coverage configuration status
        visitApp("#/overview");
        cy.contains(".overview-metric-row", "UniFi SIEM ingest")
            .find(".badge")
            .should("have.class", "badge-low")
            .and("contain.text", "Configured");

        // 2. Verify Flow Explorer collector badge, select element filtering
        visitApp("#/traffic");
        cy.get("#flow-explorer-collector").should("be.visible");
        cy.get("#flow-explorer-collector").find("option").should("have.length", 3); // All + unifi-gateway + pcap:br0
        cy.get("#tbl-flow-explorer tbody tr").should("have.length", 2);

        // Filter by unifi-gateway
        cy.get("#flow-explorer-collector").select("unifi-gateway");
        cy.get("#tbl-flow-explorer tbody tr").should("have.length", 1);
        cy.contains("#tbl-flow-explorer tbody tr", "unifi-gateway").should("exist");

        // 3. Verify device detail view contains the new UniFi SIEM events list
        visitApp("#/devices");
        cy.contains("#tbl-devices tbody tr", "192.168.30.210").find(".btn-select-device").click();
        cy.location("hash").should("eq", "#/devices/192.168.30.210");
        cy.contains("Recent UniFi SIEM Events").should("be.visible");
        cy.get("#device-unifi-events-list").within(() => {
            cy.contains(".badge", "Security Detections").should("be.visible");
            cy.contains("IDS Alert: Trojan detected").should("be.visible");
            cy.contains("192.168.30.1").should("be.visible");
        });
    });
});
