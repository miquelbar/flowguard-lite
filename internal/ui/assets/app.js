// FlowGuard Lite Dashboard Logic Engine
document.addEventListener("DOMContentLoaded", () => {
    let activeView = "dashboard";
    const routeViews = {
        "#/traffic": "dashboard",
        "#/dashboard": "dashboard",
        "#/devices": "devices",
        "#/alerts": "anomalies",
        "#/anomalies": "anomalies",
        "#/audit": "audit",
        "#/settings": "settings"
    };

    const viewRoutes = {
        "dashboard": "#/traffic",
        "devices": "#/devices",
        "anomalies": "#/alerts",
        "audit": "#/audit",
        "settings": "#/settings"
    };
    let activeTab = "sources";
    let activeTriageFilter = "all";
    let autoRefreshTimer = null;
    
    // In-memory data states
    let talkersData = [];
    let exportersData = [];
    let devicesData = [];
    let anomaliesData = [];
    let riskDevicesData = [];
    let trafficSeriesData = [];
    let activeTrafficRange = "24h";
    let activeTrafficMetric = "bytes";
    let selectedDeviceIP = null;
    let selectedAnomalyId = null;
    let auditLogPage = 0;
    const auditLogPageSize = 10;

    // Navigation elements
    const navDashboard = document.getElementById("nav-dashboard");
    const navDevices = document.getElementById("nav-devices");
    const navAnomalies = document.getElementById("nav-anomalies");
    const navAudit = document.getElementById("nav-audit");
    const navSettings = document.getElementById("nav-settings");
    
    const viewDashboard = document.getElementById("view-dashboard");
    const viewDevices = document.getElementById("view-devices");
    const viewAnomalies = document.getElementById("view-anomalies");
    const viewAudit = document.getElementById("view-audit");
    const viewSettings = document.getElementById("view-settings");
    const viewWizard = document.getElementById("view-wizard");

    // Elements
    const btnRefresh = document.getElementById("btn-refresh");
    const btnToggleSidebar = document.getElementById("btn-toggle-sidebar");
    const btnShowSidebar = document.getElementById("btn-show-sidebar");
    const btnLogout = document.getElementById("btn-logout");
    const statusIndicator = document.querySelector(".status-indicator");
    const statusLabel = document.querySelector(".status-label");
    const themeButtons = document.querySelectorAll(".theme-toggle-btn");
    const workspaceTitle = document.getElementById("workspace-title");
    const workspaceSubtitle = document.querySelector(".workspace-subtitle");
    const inputSearch = document.getElementById("input-search");
    const inputDeviceSearch = document.getElementById("input-device-search");
    const trafficChart = document.getElementById("traffic-chart");
    const trafficChartEmpty = document.getElementById("traffic-chart-empty");
    const trafficRangeButtons = document.querySelectorAll(".traffic-range-btn");
    const trafficMetricButtons = document.querySelectorAll(".traffic-metric-btn");
    const topTalkerSignal = document.getElementById("top-talker-signal");
    const portDistributionSignal = document.getElementById("port-distribution-signal");
    const subnetSummarySignal = document.getElementById("subnet-summary-signal");
    const authOverlay = document.getElementById("auth-overlay");
    const formAuth = document.getElementById("form-auth");
    const authPassword = document.getElementById("auth-password");
    const authTitle = document.getElementById("auth-title");
    const authSubtitle = document.getElementById("auth-subtitle");
    const authMessage = document.getElementById("auth-message");
    const btnAuthSubmit = document.getElementById("btn-auth-submit");
    let authMode = "login";
    
    // Stats elements
    const valPackets = document.getElementById("val-packets");
    const valDrops = document.getElementById("val-drops");
    const valErrors = document.getElementById("val-errors");
    const valQueue = document.getElementById("val-queue");

    // Table elements
    const tblExporters = document.getElementById("tbl-exporters").querySelector("tbody");
    const tblTopTalkers = document.getElementById("tbl-top-talkers").querySelector("tbody");
    const tblDevices = document.getElementById("tbl-devices").querySelector("tbody");
    const tblAnomalies = document.getElementById("tbl-anomalies").querySelector("tbody");
    const tblThreatRisk = document.getElementById("tbl-threat-risk").querySelector("tbody");
    
    const tabButtons = document.querySelectorAll(".tab-btn");
    const triageFilterButtons = document.querySelectorAll(".triage-filter-btn");

    // Device Detail elements
    const detailsEmpty = document.getElementById("device-details-empty");
    const detailsContent = document.getElementById("device-details-content");
    const detailIp = document.getElementById("detail-ip");
    const detailHost = document.getElementById("detail-host");
    const formUpdateLabel = document.getElementById("form-update-label");
    const inputDetailLabel = document.getElementById("input-detail-label");
    const baselineStatsContent = document.getElementById("baseline-stats-content");
    const detailRiskBadgeContainer = document.getElementById("detail-risk-badge-container");

    // Anomaly Detail elements
    const anomalyDetailsEmpty = document.getElementById("anomaly-details-empty");
    const anomalyDetailsContent = document.getElementById("anomaly-details-content");
    const anomalyDetailIp = document.getElementById("anomaly-detail-ip");
    const anomalyDetailType = document.getElementById("anomaly-detail-type");
    const anomalyDetailDescription = document.getElementById("anomaly-detail-description");
    const anomalyDetailTime = document.getElementById("anomaly-detail-time");
    const anomalyDetailStatus = document.getElementById("anomaly-detail-status");
    const anomalyDetailActions = document.getElementById("anomaly-detail-actions");
    const anomalyDetailBadgeContainer = document.getElementById("anomaly-detail-badge-container");

    // Toast elements
    const toastContainer = document.getElementById("toast-container");

    // Helper: format bytes into human-readable representation
    function formatBytes(bytes) {
        if (bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB", "TB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    // Helper: format numbers with comma grouping
    function formatNumber(num) {
        return num.toLocaleString();
    }

    // Helper: format date/time string
    function formatTime(isoStr) {
        if (!isoStr) return "-";
        const date = new Date(isoStr);
        return date.toLocaleTimeString() + " " + date.toLocaleDateString();
    }

    function formatShortTime(date) {
        return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }

    // Helper: show toast notification
    function showToast(message, type = "success") {
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.textContent = message;
        toastContainer.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = "0";
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    function showAuthOverlay(mode, message = "") {
        authMode = mode;
        if (!authOverlay) return;
        authTitle.textContent = mode === "setup" ? "Set Admin Password" : "FlowGuard Lite";
        authSubtitle.textContent = mode === "setup"
            ? "Create the local admin password for this FlowGuard node"
            : "Sign in to this FlowGuard node";
        btnAuthSubmit.textContent = mode === "setup" ? "Create Password" : "Sign In";
        authPassword.value = "";
        authPassword.autocomplete = mode === "setup" ? "new-password" : "current-password";
        authMessage.textContent = message;
        authOverlay.classList.remove("hidden");
        authPassword.focus();
    }

    function hideAuthOverlay() {
        if (authOverlay) authOverlay.classList.add("hidden");
    }

    async function fetchAuthStatus() {
        const resp = await fetch("/api/auth/status");
        if (!resp.ok) throw new Error("Authentication status check failed");
        return resp.json();
    }

    async function submitAuth(password) {
        const endpoint = authMode === "setup" ? "/api/auth/setup" : "/api/auth/login";
        const resp = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password })
        });
        if (!resp.ok) {
            let msg = "Authentication failed";
            try {
                const err = await resp.json();
                msg = err.error || msg;
            } catch (_) {
                // Keep generic message if server did not return JSON.
            }
            throw new Error(msg);
        }
        return resp.json();
    }

    formAuth.addEventListener("submit", async (e) => {
        e.preventDefault();
        const password = authPassword.value;
        try {
            authMessage.textContent = "";
            await submitAuth(password);
            hideAuthOverlay();
            await initAuthenticatedApp();
        } catch (err) {
            authMessage.textContent = err.message;
        }
    });

    if (btnLogout) {
        btnLogout.addEventListener("click", async () => {
            try {
                await fetch("/api/auth/logout", { method: "POST" });
            } finally {
                if (autoRefreshTimer) {
                    clearInterval(autoRefreshTimer);
                    autoRefreshTimer = null;
                }
                showAuthOverlay("login", "Signed out.");
            }
        });
    }

    // Fetch Stats & Health counters
    async function fetchHealth() {
        try {
            const resp = await fetch("/api/health");
            if (!resp.ok) throw new Error("Health check failed");
            const data = await resp.json();
            
            if (data.collector) {
                valPackets.textContent = formatNumber(data.collector.packets_received);
                valDrops.textContent = formatNumber(data.collector.packets_dropped);
                valErrors.textContent = formatNumber(data.collector.decode_errors);
                valQueue.textContent = formatNumber(data.collector.queue_depth);
            }

            if (statusIndicator) {
                statusIndicator.classList.remove("offline");
                statusIndicator.classList.add("online");
            }
            if (statusLabel) {
                statusLabel.textContent = "Collector running";
            }
        } catch (err) {
            console.error("Error fetching health: ", err);
            if (statusIndicator) {
                statusIndicator.classList.remove("online");
                statusIndicator.classList.add("offline");
            }
            if (statusLabel) {
                statusLabel.textContent = "Disconnected";
            }
        }
    }

    // Fetch Exporter registry
    async function fetchExporters() {
        try {
            const resp = await fetch("/api/exporters");
            if (!resp.ok) throw new Error("Exporters query failed");
            exportersData = await resp.json();
            renderExporters();
        } catch (err) {
            console.error("Error fetching exporters: ", err);
        }
    }

    // Fetch Top Talkers depending on active tab
    async function fetchTopTalkers() {
        try {
            const range = trafficRangeConfig();
            const params = new URLSearchParams({
                limit: "50",
                start: range.start.toISOString(),
                end: range.end.toISOString()
            });
            const resp = await fetch(`/api/top/${activeTab}?${params.toString()}`);
            if (!resp.ok) throw new Error("Top query failed");
            talkersData = await resp.json();
            renderTopTalkers();
        } catch (err) {
            console.error(`Error fetching top ${activeTab}: `, err);
        }
    }

    // Fetch Device Inventory list
    async function fetchDevices() {
        try {
            const resp = await fetch("/api/devices");
            if (!resp.ok) throw new Error("Devices query failed");
            devicesData = await resp.json();
            renderDevices();
        } catch (err) {
            console.error("Error fetching devices: ", err);
        }
    }

    // Fetch Threat Risk Scoring ranks
    async function fetchThreatRisk() {
        try {
            const resp = await fetch("/api/risk/devices");
            if (!resp.ok) throw new Error("Risk query failed");
            riskDevicesData = await resp.json();
            renderThreatRisk();
        } catch (err) {
            console.error("Error fetching threat risk scores: ", err);
        }
    }

    // Fetch Anomalies list
    async function fetchAnomalies() {
        try {
            const resp = await fetch("/api/anomalies?limit=100");
            if (!resp.ok) throw new Error("Anomalies query failed");
            anomaliesData = await resp.json();
            renderAnomalies();

            if (selectedAnomalyId) {
                const anom = anomaliesData.find(a => a.id.toString() === selectedAnomalyId);
                if (anom) {
                    selectAnomaly(selectedAnomalyId);
                } else {
                    selectedAnomalyId = null;
                    anomalyDetailsEmpty.classList.remove("hidden");
                    anomalyDetailsContent.classList.add("hidden");
                }
            }
        } catch (err) {
            console.error("Error fetching anomalies: ", err);
        }
    }

    function trafficRangeConfig() {
        const end = new Date();
        const configs = {
            "1h": { start: new Date(end.getTime() - 60 * 60 * 1000), bucket: 60 },
            "6h": { start: new Date(end.getTime() - 6 * 60 * 60 * 1000), bucket: 300 },
            "24h": { start: new Date(end.getTime() - 24 * 60 * 60 * 1000), bucket: 900 },
            "7d": { start: new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000), bucket: 3600 }
        };
        return { ...configs[activeTrafficRange], end };
    }

    async function fetchTrafficTimeSeries() {
        try {
            const range = trafficRangeConfig();
            const params = new URLSearchParams({
                start: range.start.toISOString(),
                end: range.end.toISOString(),
                bucket_seconds: String(range.bucket)
            });
            const resp = await fetch(`/api/traffic/timeseries?${params.toString()}`);
            if (!resp.ok) throw new Error("Traffic time-series query failed");
            trafficSeriesData = await resp.json();
            renderTrafficChart();
        } catch (err) {
            console.error("Error fetching traffic time series: ", err);
            trafficSeriesData = [];
            renderTrafficChart();
        }
    }

    function renderTrafficChart() {
        if (!trafficChart) return;
        const width = 900;
        const height = 260;
        const pad = { top: 18, right: 22, bottom: 32, left: 74 };
        const plotW = width - pad.left - pad.right;
        const plotH = height - pad.top - pad.bottom;
        trafficChart.innerHTML = "";

        const points = (trafficSeriesData || []).map(item => ({
            ts: new Date(item.timestamp).getTime(),
            value: Number(item[activeTrafficMetric] || 0),
            raw: item
        })).filter(item => Number.isFinite(item.ts));

        if (trafficChartEmpty) trafficChartEmpty.classList.toggle("hidden", points.length > 0);
        if (points.length === 0) {
            trafficChart.innerHTML = `<text x="${width / 2}" y="${height / 2}" text-anchor="middle" class="chart-muted">No data</text>`;
            renderNetworkSignals();
            return;
        }

        const minTs = Math.min(...points.map(p => p.ts));
        const maxTs = Math.max(...points.map(p => p.ts));
        const maxValue = Math.max(...points.map(p => p.value), 1);
        const tsSpan = Math.max(maxTs - minTs, 1);
        const xFor = ts => pad.left + ((ts - minTs) / tsSpan) * plotW;
        const yFor = value => pad.top + plotH - (value / maxValue) * plotH;

        const gridLines = [0, 0.25, 0.5, 0.75, 1].map(frac => {
            const y = pad.top + plotH - (frac * plotH);
            const label = activeTrafficMetric === "bytes" ? formatBytes(maxValue * frac) : formatNumber(Math.round(maxValue * frac));
            return `<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" class="chart-grid"></line>
                    <text x="${pad.left - 10}" y="${y + 4}" text-anchor="end" class="chart-axis">${label}</text>`;
        }).join("");

        const pathData = points.map((p, idx) => `${idx === 0 ? "M" : "L"} ${xFor(p.ts).toFixed(2)} ${yFor(p.value).toFixed(2)}`).join(" ");
        const areaData = `${pathData} L ${xFor(points[points.length - 1].ts).toFixed(2)} ${pad.top + plotH} L ${xFor(points[0].ts).toFixed(2)} ${pad.top + plotH} Z`;
        const firstLabel = formatShortTime(new Date(minTs));
        const lastLabel = formatShortTime(new Date(maxTs));
        const singleSampleGuide = points.length === 1
            ? `<line x1="${xFor(points[0].ts).toFixed(2)}" y1="${pad.top}" x2="${xFor(points[0].ts).toFixed(2)}" y2="${pad.top + plotH}" class="chart-sample-guide"></line>`
            : "";

        const anomalyMarkers = (anomaliesData || []).map(anom => {
            const ts = new Date(anom.created_at).getTime();
            if (!Number.isFinite(ts) || ts < minTs || ts > maxTs) return "";
            const x = xFor(ts);
            const colorClass = anom.severity === "high" ? "chart-marker-high" : "chart-marker-medium";
            return `<line x1="${x}" y1="${pad.top}" x2="${x}" y2="${pad.top + plotH}" class="chart-marker ${colorClass}">
                    <title>${anom.type}: ${anom.ip}</title></line>`;
        }).join("");

        trafficChart.innerHTML = `
            <defs>
                <linearGradient id="trafficAreaFill" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stop-color="currentColor" stop-opacity="0.20"></stop>
                    <stop offset="100%" stop-color="currentColor" stop-opacity="0.02"></stop>
                </linearGradient>
            </defs>
            ${gridLines}
            <path d="${areaData}" class="chart-area"></path>
            <path d="${pathData}" class="chart-line"></path>
            ${singleSampleGuide}
            ${points.map(p => `<circle cx="${xFor(p.ts).toFixed(2)}" cy="${yFor(p.value).toFixed(2)}" r="${points.length === 1 ? 4.5 : 2.3}" class="chart-point"><title>${formatTime(p.raw.timestamp)} - ${activeTrafficMetric}: ${activeTrafficMetric === "bytes" ? formatBytes(p.value) : formatNumber(p.value)}</title></circle>`).join("")}
            ${anomalyMarkers}
            <text x="${pad.left}" y="${height - 8}" class="chart-axis">${firstLabel}</text>
            <text x="${width - pad.right}" y="${height - 8}" text-anchor="end" class="chart-axis">${lastLabel}</text>
        `;
        renderNetworkSignals();
    }

    function renderNetworkSignals() {
        renderTopTalkerSignal();
        renderPortDistributionSignal();
        renderSubnetSummarySignal();
    }

    function renderTopTalkerSignal() {
        if (!topTalkerSignal) return;
        const range = trafficRangeConfig();
        const params = new URLSearchParams({
            limit: "3",
            start: range.start.toISOString(),
            end: range.end.toISOString()
        });
        fetch(`/api/top/sources?${params.toString()}`)
            .then(resp => resp.ok ? resp.json() : [])
            .then(sources => {
                const sortedSources = [...sources].sort((a, b) => b.bytes - a.bytes);
                if (sortedSources.length === 0) {
                    topTalkerSignal.textContent = "No top talker data in the active window.";
                    return;
                }
                const totalBytes = sortedSources.reduce((sum, item) => sum + item.bytes, 0) || 1;
                topTalkerSignal.innerHTML = sortedSources.map(item => {
                    const pct = (item.bytes / totalBytes) * 100;
                    return `<div class="signal-row">
                        <span class="signal-key">${item.key}</span>
                        <span class="signal-value">${pct.toFixed(1)}%</span>
                        <div class="signal-bar"><span style="width:${Math.max(pct, 2)}%"></span></div>
                    </div>`;
                }).join("");
            })
            .catch(() => {
                topTalkerSignal.textContent = "Top talker share unavailable.";
            });
    }

    function protocolName(protocol) {
        const labels = {
            "1": "ICMP",
            "6": "TCP",
            "17": "UDP",
            "47": "GRE",
            "50": "ESP",
            "58": "ICMPv6"
        };
        return labels[String(protocol)] || `IP ${protocol}`;
    }

    function renderPortDistributionSignal() {
        if (!portDistributionSignal) return;
        const range = trafficRangeConfig();
        const params = new URLSearchParams({
            limit: "6",
            start: range.start.toISOString(),
            end: range.end.toISOString()
        });
        Promise.all([
            fetch(`/api/top/protocols?${params.toString()}`).then(resp => resp.ok ? resp.json() : []),
            fetch(`/api/top/ports?${params.toString()}`).then(resp => resp.ok ? resp.json() : [])
        ])
            .then(([protocols, ports]) => {
                if ((!protocols || protocols.length === 0) && (!ports || ports.length === 0)) {
                    portDistributionSignal.textContent = "No protocol or destination port data in the active window.";
                    return;
                }

                const protocolTotal = protocols.reduce((sum, item) => sum + item.bytes, 0) || 1;
                const portTotal = ports.reduce((sum, item) => sum + item.bytes, 0) || 1;
                const protocolRows = protocols.slice(0, 2).map(item => {
                    const pct = (item.bytes / protocolTotal) * 100;
                    return `<div class="signal-row">
                        <span class="signal-key">${protocolName(item.key)}</span>
                        <span class="signal-value">${pct.toFixed(0)}%</span>
                        <div class="signal-bar signal-bar-protocol"><span style="width:${Math.max(pct, 2)}%"></span></div>
                    </div>`;
                }).join("");
                const portRows = ports.slice(0, 3).map(item => {
                    const pct = (item.bytes / portTotal) * 100;
                    return `<div class="signal-row">
                        <span class="signal-key">:${item.key}</span>
                        <span class="signal-value">${formatBytes(item.bytes)}</span>
                        <div class="signal-bar"><span style="width:${Math.max(pct, 2)}%"></span></div>
                    </div>`;
                }).join("");

                portDistributionSignal.innerHTML = `
                    ${protocolRows ? `<div class="signal-section-label">Protocols</div>${protocolRows}` : ""}
                    ${portRows ? `<div class="signal-section-label">Destination ports</div>${portRows}` : ""}
                `;
            })
            .catch(() => {
                portDistributionSignal.textContent = "Protocol and port distribution unavailable.";
            });
    }

    function subnetLabelFor(ip) {
        const parts = ip.split(".");
        if (parts.length < 3) return "Unknown";
        return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }

    function renderSubnetSummarySignal() {
        if (!subnetSummarySignal) return;
        const summary = new Map();
        devicesData.forEach(dev => {
            const subnet = subnetLabelFor(dev.ip);
            if (!summary.has(subnet)) summary.set(subnet, { count: 0, risk: 0 });
            summary.get(subnet).count += 1;
        });
        riskDevicesData.forEach(dev => {
            const subnet = subnetLabelFor(dev.ip);
            if (!summary.has(subnet)) summary.set(subnet, { count: 0, risk: 0 });
            summary.get(subnet).risk += 1;
        });
        if (summary.size === 0) {
            subnetSummarySignal.textContent = "No discovered local subnets yet.";
            return;
        }
        subnetSummarySignal.innerHTML = [...summary.entries()].sort().slice(0, 4).map(([subnet, val]) => `
            <div class="subnet-row">
                <span class="signal-key">${subnet}</span>
                <span class="signal-value">${val.count} devices · ${val.risk} risky</span>
            </div>
        `).join("");
    }

    // Render Exporters to table
    function renderExporters() {
        if (!exportersData || exportersData.length === 0) {
            tblExporters.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No active exporters observed.</td></tr>`;
            return;
        }

        tblExporters.innerHTML = exportersData.map(exp => `
            <tr>
                <td>${exp.ip}</td>
                <td>${formatTime(exp.last_seen)}</td>
                <td class="text-right">${formatNumber(exp.packet_count)}</td>
            </tr>
        `).join('');
    }

    // Render Threat Risk Ranking to table
    function renderThreatRisk() {
        if (!riskDevicesData || riskDevicesData.length === 0) {
            tblThreatRisk.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No elevated-risk devices.</td></tr>`;
            return;
        }

        tblThreatRisk.innerHTML = riskDevicesData.map(dev => {
            const badgeClass = dev.risk_level === "high" ? "risk-badge-high" : (dev.risk_level === "medium" ? "risk-badge-medium" : "risk-badge-low");
            return `
                <tr style="cursor: pointer;" class="threat-device-row" data-ip="${dev.ip}">
                    <td>
                        <div class="risk-device-cell">
                            <span class="risk-device-ip">${dev.ip}</span>
                            ${dev.label ? `<span class="badge badge-label risk-device-label">${dev.label}</span>` : ''}
                        </div>
                    </td>
                    <td><span class="risk-badge ${badgeClass} risk-score-badge">${dev.risk_score}</span></td>
                    <td class="text-right text-muted" style="text-transform: capitalize;">${dev.risk_level}</td>
                </tr>
            `;
        }).join('');

        // Clicking a threat device row navigates to devices page and selects it
        tblThreatRisk.querySelectorAll(".threat-device-row").forEach(row => {
            row.addEventListener("click", () => {
                const ip = row.getAttribute("data-ip");
                selectedDeviceIP = ip;
                switchView("devices");
            });
        });
    }

    // Render Top Talkers to table with progress bars
    function renderTopTalkers() {
        const query = inputSearch.value.trim().toLowerCase();
        const filtered = talkersData.filter(item => item.key.toLowerCase().includes(query));

        if (filtered.length === 0) {
            tblTopTalkers.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No records match the active filters.</td></tr>`;
            return;
        }

        const maxBytes = Math.max(...filtered.map(i => i.bytes), 1);

        tblTopTalkers.innerHTML = filtered.map(item => {
            const percentage = (item.bytes / maxBytes) * 100;
            return `
                <tr>
                    <td class="font-semibold">${item.key}</td>
                    <td class="text-right">${formatNumber(item.flows)}</td>
                    <td class="text-right">${formatNumber(item.packets)}</td>
                    <td class="text-right">${formatBytes(item.bytes)}</td>
                    <td class="width-progress">
                        <div class="progress-track" title="${percentage.toFixed(1)}%">
                            <div class="progress-bar" style="width: ${percentage}%"></div>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    }

    // Render Device list to table
    function renderDevices() {
        const query = inputDeviceSearch.value.trim().toLowerCase();
        const filtered = devicesData.filter(dev => {
            return dev.ip.toLowerCase().includes(query) || 
                   (dev.hostname && dev.hostname.toLowerCase().includes(query)) ||
                   (dev.label && dev.label.toLowerCase().includes(query));
        });

        if (filtered.length === 0) {
            tblDevices.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No devices match active search filters.</td></tr>`;
            return;
        }

        tblDevices.innerHTML = filtered.map(dev => {
            const isSelected = selectedDeviceIP === dev.ip;
            return `
                <tr data-ip="${dev.ip}" class="${isSelected ? 'selected' : ''}">
                    <td class="font-semibold">${dev.ip}</td>
                    <td class="text-muted">${dev.hostname || "<i>Unresolved</i>"}</td>
                    <td>${dev.label ? `<span class="badge badge-label">${dev.label}</span>` : '<span class="text-muted">-</span>'}</td>
                    <td class="text-center">
                        <button class="btn-secondary btn-select-device" data-ip="${dev.ip}">Select</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Attach select click listeners to row and action button
        tblDevices.querySelectorAll("tr").forEach(row => {
            row.addEventListener("click", (e) => {
                if (e.target.tagName === "BUTTON") return;
                const ip = row.getAttribute("data-ip");
                selectDevice(ip);
            });
        });

        tblDevices.querySelectorAll(".btn-select-device").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const ip = e.target.getAttribute("data-ip");
                selectDevice(ip);
            });
        });
    }

    // Select device and load baseline details
    async function selectDevice(ip) {
        selectedDeviceIP = ip;
        renderDevices(); // Highlight row
        
        const dev = devicesData.find(d => d.ip === ip);
        if (!dev) return;

        detailsEmpty.classList.add("hidden");
        detailsContent.classList.remove("hidden");
        
        detailIp.textContent = dev.ip;
        detailHost.textContent = dev.hostname ? `Reverse DNS: ${dev.hostname}` : "Reverse DNS: Unresolved";
        inputDetailLabel.value = dev.label || "";

        // Display current active risk badge
        const riskDev = riskDevicesData.find(r => r.ip === ip);
        if (riskDev) {
            const badgeClass = riskDev.risk_level === "high" ? "risk-badge-high" : (riskDev.risk_level === "medium" ? "risk-badge-medium" : "risk-badge-low");
            detailRiskBadgeContainer.innerHTML = `<span class="risk-badge ${badgeClass}" title="Active alerts: ${riskDev.active_alert_count}">Risk Index: ${riskDev.risk_score}</span>`;
        } else {
            detailRiskBadgeContainer.innerHTML = `<span class="risk-badge risk-badge-low">Risk Index: 0</span>`;
        }

        // Fetch behavioral baseline
        baselineStatsContent.innerHTML = `<p class="text-muted text-center">Loading baseline profile...</p>`;
        
        try {
            const resp = await fetch(`/api/devices/${ip}/baseline`);
            if (resp.status === 404) {
                baselineStatsContent.innerHTML = `
                    <div class="text-center text-muted pad-large" style="border: 1px dashed rgba(255,255,255,0.08); border-radius: 8px;">
                        No baseline computed yet.<br>
                        <span style="font-size: 0.75rem;">Profile will generate once at least 5 minutes of active traffic flows are aggregated.</span>
                    </div>
                `;
                return;
            }
            if (!resp.ok) throw new Error("Failed fetching device baseline");
            const baseline = await resp.json();

            const byteLimit = baseline.mean_bytes + (3 * baseline.stddev_bytes);
            const packetLimit = baseline.mean_packets + (3 * baseline.stddev_packets);
            const peerLimit = baseline.mean_peers + (3 * baseline.stddev_peers);

            baselineStatsContent.innerHTML = `
                <div class="baseline-stat-row">
                    <span class="metric-name">Average Bytes/Min</span>
                    <span class="metric-value">${formatBytes(baseline.mean_bytes)}</span>
                </div>
                <div class="baseline-stat-row">
                    <span class="metric-name">Traffic Limit (Mean + 3σ)</span>
                    <span class="metric-value text-warning" style="font-weight:700;">${formatBytes(byteLimit)}</span>
                </div>
                <div class="baseline-stat-row">
                    <span class="metric-name">Average Packets/Min</span>
                    <span class="metric-value">${formatNumber(Math.round(baseline.mean_packets))} pkts</span>
                </div>
                <div class="baseline-stat-row">
                    <span class="metric-name">Packet Limit (Mean + 3σ)</span>
                    <span class="metric-value text-warning" style="font-weight:700;">${formatNumber(Math.round(packetLimit))} pkts</span>
                </div>
                <div class="baseline-stat-row">
                    <span class="metric-name">Average Peers/Min</span>
                    <span class="metric-value">${baseline.mean_peers.toFixed(1)}</span>
                </div>
                <div class="baseline-stat-row">
                    <span class="metric-name">Peer Limit (Mean + 3σ)</span>
                    <span class="metric-value text-warning" style="font-weight:700;">${Math.round(peerLimit)} peers</span>
                </div>
                <p class="text-muted text-right" style="font-size:0.75rem; margin-top:0.5rem;">
                    Baseline updated: ${formatTime(baseline.updated_at)}
                </p>
            `;
        } catch (err) {
            baselineStatsContent.innerHTML = `<p class="text-danger text-center">Failed to load baseline: ${err.message}</p>`;
        }
    }

    // Submit label update from details panel
    formUpdateLabel.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!selectedDeviceIP) return;

        const newLabel = inputDetailLabel.value.trim();

        try {
            const resp = await fetch(`/api/devices/${selectedDeviceIP}/label`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ label: newLabel })
            });

            if (!resp.ok) throw new Error("Failed to update device label");

            showToast(`Label updated for ${selectedDeviceIP}.`);
            await fetchDevices();
            const dev = devicesData.find(d => d.ip === selectedDeviceIP);
            if (dev) {
                inputDetailLabel.value = dev.label || "";
            }
        } catch (err) {
            showToast(err.message, "error");
        }
    });

    // Select an anomaly to view details in the right pane
    function selectAnomaly(id) {
        selectedAnomalyId = id.toString();
        renderAnomalies(); // Highlight selected row

        const anom = anomaliesData.find(a => a.id.toString() === selectedAnomalyId);
        if (!anom) return;

        anomalyDetailsEmpty.classList.add("hidden");
        anomalyDetailsContent.classList.remove("hidden");

        anomalyDetailIp.textContent = anom.ip;
        anomalyDetailType.textContent = anom.type;
        anomalyDetailDescription.textContent = anom.description;
        anomalyDetailTime.textContent = new Date(anom.created_at).toLocaleString();
        anomalyDetailStatus.textContent = anom.status;
        anomalyDetailStatus.className = `badge-label status-${anom.status}`;

        // Populate severity badge
        const badgeClass = anom.severity === "high" ? "badge-high" : (anom.severity === "medium" ? "badge-medium" : "badge-low");
        anomalyDetailBadgeContainer.innerHTML = `<span class="badge ${badgeClass}">${anom.severity.toUpperCase()}</span>`;

        // Populate action buttons based on status
        let buttonsHtml = "";
        if (anom.status === "active") {
            buttonsHtml = `
                <button class="btn-secondary btn-triage btn-ack" data-id="${anom.id}" data-action="acknowledged">Acknowledge</button>
                <button class="btn-secondary btn-triage btn-silence" data-id="${anom.id}" data-action="silenced">Silence</button>
                <button class="btn-primary btn-block-rules" data-ip="${anom.ip}">Firewall Template</button>
            `;
        } else {
            buttonsHtml = `
                <button class="btn-secondary btn-triage btn-reactivate" data-id="${anom.id}" data-action="active">Reactivate</button>
                <button class="btn-primary btn-block-rules" data-ip="${anom.ip}">Firewall Template</button>
            `;
        }
        anomalyDetailActions.innerHTML = buttonsHtml;

        // Bind click events on triage buttons inside the details pane
        anomalyDetailActions.querySelectorAll(".btn-triage").forEach(btn => {
            btn.addEventListener("click", async (e) => {
                const action = btn.getAttribute("data-action");
                await updateAnomalyStatus(anom.id, action);
            });
        });

        anomalyDetailActions.querySelectorAll(".btn-block-rules").forEach(btn => {
            btn.addEventListener("click", () => {
                openFirewallModal(anom.ip);
            });
        });
    }

    // Render Anomalies to table
    function renderAnomalies() {
        const searchQuery = document.getElementById("search-anomalies").value.toLowerCase().trim();
        const severityFilter = document.getElementById("filter-anomalies-severity").value;

        const filtered = anomaliesData.filter(anom => {
            // 1. Triage Status Tab filter
            if (activeTriageFilter !== "all" && anom.status !== activeTriageFilter) return false;
            // 2. Severity filter
            if (severityFilter !== "all" && anom.severity !== severityFilter) return false;
            // 3. Search query filter
            if (searchQuery !== "") {
                const ipMatch = anom.ip.toLowerCase().includes(searchQuery);
                const typeMatch = anom.type.toLowerCase().includes(searchQuery);
                const descMatch = anom.description.toLowerCase().includes(searchQuery);
                if (!ipMatch && !typeMatch && !descMatch) return false;
            }
            return true;
        });

        if (filtered.length === 0) {
            tblAnomalies.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No anomalies match selection filters.</td></tr>`;
            return;
        }

        tblAnomalies.innerHTML = filtered.map(anom => {
            const badgeClass = anom.severity === "high" ? "badge-high" : (anom.severity === "medium" ? "badge-medium" : "badge-low");
            const statusClass = `status-${anom.status}`;
            const isSelected = selectedAnomalyId === anom.id.toString();
            
            return `
                <tr class="anomaly-row ${isSelected ? 'selected' : ''}" data-id="${anom.id}" style="cursor: pointer;">
                    <td class="font-semibold">${anom.ip}</td>
                    <td><span class="badge ${badgeClass}">${anom.type}</span></td>
                    <td style="text-transform: capitalize;"><span class="sev-dot sev-${anom.severity}"></span>${anom.severity}</td>
                    <td>${formatTime(anom.created_at)}</td>
                    <td><span class="${statusClass}">${anom.status}</span></td>
                    <td class="text-center">
                        <button class="btn-secondary btn-select-anomaly" data-id="${anom.id}">Select</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Attach select click listeners to row and select button
        tblAnomalies.querySelectorAll("tr").forEach(row => {
            row.addEventListener("click", (e) => {
                if (e.target.tagName === "BUTTON") return;
                const id = row.getAttribute("data-id");
                if (id) selectAnomaly(id);
            });
        });

        tblAnomalies.querySelectorAll(".btn-select-anomaly").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const id = e.target.getAttribute("data-id");
                selectAnomaly(id);
            });
        });
    }

    // Submit triage action PUT request
    async function updateAnomalyStatus(id, newStatus) {
        try {
            const resp = await fetch(`/api/anomalies/${id}/status`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ status: newStatus })
            });

            if (!resp.ok) throw new Error("Failed to update alert status");

            showToast(`Alert status updated to ${newStatus}.`);
            await Promise.all([
                fetchAnomalies(),
                fetchThreatRisk()
            ]);
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    // Fetch system audit logs from API
    let auditLogsData = [];
    async function fetchAuditLogs() {
        try {
            const resp = await fetch("/api/audit-logs?limit=100");
            if (!resp.ok) throw new Error("Failed to query audit logs");
            auditLogsData = await resp.json();
            renderAuditLogs();
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    // Render audit logs into UI table
    function renderAuditLogs() {
        const tblAuditLogs = document.getElementById("tbl-audit-logs").querySelector("tbody");
        if (!tblAuditLogs) return;

        const searchQuery = document.getElementById("search-audit-logs").value.toLowerCase().trim();

        // 1. Filter
        const filtered = auditLogsData.filter(log => {
            if (searchQuery === "") return true;
            return log.action.toLowerCase().includes(searchQuery) || log.details.toLowerCase().includes(searchQuery);
        });

        // 2. Paginate
        const total = filtered.length;
        const totalPages = Math.ceil(total / auditLogPageSize) || 1;
        
        if (auditLogPage >= totalPages) {
            auditLogPage = totalPages - 1;
        }
        if (auditLogPage < 0) {
            auditLogPage = 0;
        }

        const startIdx = auditLogPage * auditLogPageSize;
        const endIdx = Math.min(startIdx + auditLogPageSize, total);
        const pageData = filtered.slice(startIdx, endIdx);

        // Update stats text
        const statsEl = document.getElementById("audit-pagination-stats");
        if (statsEl) {
            if (total === 0) {
                statsEl.textContent = "Showing 0-0 of 0 logs";
            } else {
                statsEl.textContent = `Showing ${startIdx + 1}-${endIdx} of ${total} logs`;
            }
        }

        // Update pagination buttons state
        const btnPrev = document.getElementById("btn-audit-prev");
        const btnNext = document.getElementById("btn-audit-next");
        if (btnPrev) btnPrev.disabled = (auditLogPage === 0);
        if (btnNext) btnNext.disabled = (auditLogPage >= totalPages - 1);

        if (pageData.length === 0) {
            tblAuditLogs.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No audit logs match filters.</td></tr>`;
            return;
        }

        tblAuditLogs.innerHTML = pageData.map(log => `
            <tr>
                <td style="white-space: nowrap;">${new Date(log.timestamp).toLocaleString()}</td>
                <td><span class="badge badge-label">${log.action}</span></td>
                <td>${log.details}</td>
            </tr>
        `).join("");
    }

    // Modal Firewall logic
    let firewallTemplates = null;
    let activeFwTab = "mikrotik";

    async function openFirewallModal(ip) {
        const modal = document.getElementById("modal-firewall");
        const targetIpField = document.getElementById("firewall-target-ip");
        const codeContent = document.getElementById("firewall-code-content");
        
        targetIpField.value = ip;
        codeContent.textContent = "Loading rules...";
        activeFwTab = "mikrotik";
        
        // Reset tab active state in modal
        document.querySelectorAll(".fw-tab-btn").forEach(btn => {
            if (btn.getAttribute("data-fw") === "mikrotik") {
                btn.classList.add("active");
            } else {
                btn.classList.remove("active");
            }
        });

        modal.showModal();

        try {
            const resp = await fetch(`/api/firewall/rules?ip=${ip}`);
            if (!resp.ok) throw new Error("Failed to load firewall templates");
            firewallTemplates = await resp.json();
            renderFirewallCode();
        } catch (err) {
            codeContent.textContent = `Error: ${err.message}`;
            showToast(err.message, "error");
        }
    }

    function renderFirewallCode() {
        const codeContent = document.getElementById("firewall-code-content");
        if (!firewallTemplates) return;
        codeContent.textContent = firewallTemplates[activeFwTab] || "No template configured.";
    }

    // Setup modal button handlers
    const btnCloseModal = document.getElementById("btn-close-modal");
    if (btnCloseModal) {
        btnCloseModal.addEventListener("click", () => {
            document.getElementById("modal-firewall").close();
        });
    }

    const btnCopyRules = document.getElementById("btn-copy-rules");
    if (btnCopyRules) {
        btnCopyRules.addEventListener("click", () => {
            const code = document.getElementById("firewall-code-content").textContent;
            navigator.clipboard.writeText(code).then(() => {
            showToast("Rules copied.");
            }).catch(err => {
                showToast("Copy failed: " + err, "error");
            });
        });
    }

    document.querySelectorAll(".fw-tab-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            document.querySelectorAll(".fw-tab-btn").forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeFwTab = e.target.getAttribute("data-fw");
            renderFirewallCode();
        });
    });

    // Perform full page data fetch
    async function loadData() {
        // Fetch health unconditionally so status indicator updates on every view
        await fetchHealth();

        // Fetch threat risk ranks unconditionally as they affect indicators and badges across multiple views
        await fetchThreatRisk();

        if (activeView === "dashboard") {
            await Promise.all([
                fetchExporters(),
                fetchTopTalkers(),
                fetchDevices(),
                fetchAnomalies(),
                fetchTrafficTimeSeries()
            ]);
            renderNetworkSignals();
        } else if (activeView === "devices") {
            await fetchDevices();
            if (selectedDeviceIP) {
                const dev = devicesData.find(d => d.ip === selectedDeviceIP);
                if (dev) {
                    selectDevice(selectedDeviceIP);
                }
            }
        } else if (activeView === "anomalies") {
            await fetchAnomalies();
        } else if (activeView === "audit") {
            await fetchAuditLogs();
        } else if (activeView === "settings") {
            await fetchSettings();
        }
    }

    // Switch between SPA views
    function switchView(viewName) {
        activeView = viewName;
        const targetHash = viewRoutes[viewName];
        if (targetHash && window.location.hash !== targetHash) {
            window.location.hash = targetHash;
        }

        const titles = {
            dashboard: ["Traffic", "Flow telemetry, risk signals, and local device activity"],
            devices: ["Devices", "Local inventory, labels, and learned baselines"],
            anomalies: ["Alerts", "Behavior changes that need review"],
            audit: ["Audit", "Configuration changes and alert review history"],
            settings: ["Settings", "Runtime configuration for this FlowGuard node"]
        };
        const title = titles[viewName] || titles.dashboard;
        if (workspaceTitle) workspaceTitle.textContent = title[0];
        if (workspaceSubtitle) workspaceSubtitle.textContent = title[1];
        
        // Remove active class from all nav links
        navDashboard.classList.remove("active");
        navDevices.classList.remove("active");
        navAnomalies.classList.remove("active");
        navAudit.classList.remove("active");
        navSettings.classList.remove("active");

        // Hide all views
        viewDashboard.classList.remove("active");
        viewDevices.classList.remove("active");
        viewAnomalies.classList.remove("active");
        viewAudit.classList.remove("active");
        viewSettings.classList.remove("active");

        if (viewName === "dashboard") {
            navDashboard.classList.add("active");
            viewDashboard.classList.add("active");
        } else if (viewName === "devices") {
            navDevices.classList.add("active");
            viewDevices.classList.add("active");
        } else if (viewName === "anomalies") {
            navAnomalies.classList.add("active");
            viewAnomalies.classList.add("active");
        } else if (viewName === "audit") {
            navAudit.classList.add("active");
            viewAudit.classList.add("active");
        } else if (viewName === "settings") {
            navSettings.classList.add("active");
            viewSettings.classList.add("active");
        }
        
        loadData();
    }

    // Navigation Button Listeners
    navDashboard.addEventListener("click", () => { window.location.hash = "#/traffic"; });
    navDevices.addEventListener("click", () => { window.location.hash = "#/devices"; });
    navAnomalies.addEventListener("click", () => { window.location.hash = "#/alerts"; });
    navAudit.addEventListener("click", () => { window.location.hash = "#/audit"; });
    navSettings.addEventListener("click", () => { window.location.hash = "#/settings"; });

    // Handle URL Hash changes
    window.addEventListener("hashchange", () => {
        const hash = window.location.hash || "#/traffic";
        const viewName = routeViews[hash] || "dashboard";
        switchView(viewName);
    });

    // Handle Manual Refresh
    btnRefresh.addEventListener("click", () => {
        loadData();
    });

    function applyStoredShellPreferences() {
        const sidebarCollapsed = localStorage.getItem("fg_sidebar_collapsed") === "true";
        const darkMode = localStorage.getItem("fg_theme") === "dark";

        document.body.classList.toggle("sidebar-collapsed", sidebarCollapsed);
        document.body.classList.toggle("dark-mode", darkMode);

        if (btnToggleSidebar) {
            const toolText = btnToggleSidebar.querySelector(".tool-text");
            if (toolText) {
                toolText.textContent = sidebarCollapsed ? "Expand" : "Collapse";
            }
            btnToggleSidebar.setAttribute("title", sidebarCollapsed ? "Expand Sidebar" : "Collapse Sidebar");
        }

        updateThemeButtons(darkMode);
    }

    function updateThemeButtons(darkMode) {
        themeButtons.forEach(btn => {
            const toolText = btn.querySelector(".tool-text");
            if (toolText) {
                toolText.textContent = darkMode ? "Light Mode" : "Dark Mode";
            }
            const svg = btn.querySelector("svg");
            if (svg) {
                if (darkMode) {
                    svg.innerHTML = `<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>`;
                } else {
                    svg.innerHTML = `<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>`;
                }
            }
        });
    }

    if (btnToggleSidebar) {
        btnToggleSidebar.addEventListener("click", () => {
            const collapsed = !document.body.classList.contains("sidebar-collapsed");
            document.body.classList.toggle("sidebar-collapsed", collapsed);
            localStorage.setItem("fg_sidebar_collapsed", collapsed ? "true" : "false");
            
            const toolText = btnToggleSidebar.querySelector(".tool-text");
            if (toolText) {
                toolText.textContent = collapsed ? "Expand" : "Collapse";
            }
            btnToggleSidebar.setAttribute("title", collapsed ? "Expand Sidebar" : "Collapse Sidebar");
        });
    }

    themeButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const darkMode = !document.body.classList.contains("dark-mode");
            document.body.classList.toggle("dark-mode", darkMode);
            localStorage.setItem("fg_theme", darkMode ? "dark" : "light");
            updateThemeButtons(darkMode);
        });
    });

    // Handle Search input filtering
    inputSearch.addEventListener("input", () => renderTopTalkers());
    inputDeviceSearch.addEventListener("input", () => renderDevices());

    // Handle Tab buttons click for Top Talkers
    tabButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            tabButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeTab = e.target.getAttribute("data-tab");
            fetchTopTalkers();
        });
    });

    trafficRangeButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            trafficRangeButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeTrafficRange = e.target.getAttribute("data-range");
            fetchTrafficTimeSeries();
        });
    });

    trafficMetricButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            trafficMetricButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeTrafficMetric = e.target.getAttribute("data-metric");
            renderTrafficChart();
        });
    });

    // Handle triage status filter buttons
    triageFilterButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            triageFilterButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeTriageFilter = e.target.getAttribute("data-status");
            renderAnomalies();
        });
    });

    // Handle Search/Filter for anomalies
    document.getElementById("search-anomalies").addEventListener("input", () => {
        renderAnomalies();
    });
    document.getElementById("filter-anomalies-severity").addEventListener("change", () => {
        renderAnomalies();
    });

    document.getElementById("btn-close-anomaly-details").addEventListener("click", () => {
        selectedAnomalyId = null;
        anomalyDetailsEmpty.classList.remove("hidden");
        anomalyDetailsContent.classList.add("hidden");
        renderAnomalies();
    });

    document.getElementById("btn-close-device-details").addEventListener("click", () => {
        selectedDeviceIP = null;
        detailsEmpty.classList.remove("hidden");
        detailsContent.classList.add("hidden");
        renderDevices();
    });

    // Handle Search/Pagination for audit logs
    document.getElementById("search-audit-logs").addEventListener("input", () => {
        auditLogPage = 0;
        renderAuditLogs();
    });
    document.getElementById("btn-audit-prev").addEventListener("click", () => {
        if (auditLogPage > 0) {
            auditLogPage--;
            renderAuditLogs();
        }
    });
    document.getElementById("btn-audit-next").addEventListener("click", () => {
        auditLogPage++;
        renderAuditLogs();
    });

    // Webhook custom headers dynamic list editor
    document.getElementById("btn-add-webhook-header").addEventListener("click", () => {
        appendWebhookHeaderRow("", "");
    });

    let settingsData = null;

    async function fetchSettings() {
        try {
            const resp = await fetch("/api/settings");
            if (resp.status === 401) {
                showAuthOverlay("login", "Session expired. Sign in again.");
                return;
            }
            if (!resp.ok) throw new Error("Settings fetch failed");
            settingsData = await resp.json();
            
            // Check first run status
            if (!settingsData.first_run_completed) {
                viewWizard.classList.remove("hidden");
                if (autoRefreshTimer) {
                    clearInterval(autoRefreshTimer);
                    autoRefreshTimer = null;
                }
            } else {
                viewWizard.classList.add("hidden");
            }

            // Populate settings inputs
            document.getElementById("setting-subnets").value = settingsData.local_subnets.join(", ");
            document.getElementById("setting-netflow").value = settingsData.netflow_port;
            document.getElementById("setting-sflow").value = settingsData.sflow_port;
            document.getElementById("setting-backend").value = settingsData.storage_backend;
            document.getElementById("setting-webhook-url").value = settingsData.webhook_url;
            document.getElementById("setting-webhook-format").value = settingsData.webhook_format;
            document.getElementById("setting-telegram-enabled").checked = settingsData.telegram_enabled;
            document.getElementById("setting-telegram-token").value = settingsData.telegram_token || "";
            document.getElementById("setting-telegram-chat-id").value = settingsData.telegram_chat_id || "";
            renderWebhookHeaders(settingsData.webhook_headers || {});
        } catch (err) {
            console.error("Error fetching settings: ", err);
        }
    }

    async function saveSettings(payload) {
        try {
            const resp = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || "Save settings failed");
            }
            
            let note = "";
            if (settingsData && (payload.netflow_port !== settingsData.netflow_port || payload.sflow_port !== settingsData.sflow_port)) {
                note = " (Note: Port changes require a daemon restart to take effect)";
            }
            showToast("Settings saved." + note);
            await fetchSettings();
        } catch (err) {
            showToast("Settings save failed: " + err.message, "error");
        }
    }

    // Settings Network Form Submit
    document.getElementById("form-settings-network").addEventListener("submit", (e) => {
        e.preventDefault();
        if (!settingsData) return;
        const subnets = document.getElementById("setting-subnets").value.split(",").map(s => s.trim()).filter(s => s !== "");
        const netflow = parseInt(document.getElementById("setting-netflow").value, 10);
        const sflow = parseInt(document.getElementById("setting-sflow").value, 10);
        
        const payload = {
            ...settingsData,
            local_subnets: subnets,
            netflow_port: netflow,
            sflow_port: sflow
        };
        saveSettings(payload);
    });

    // Settings Storage Form Submit
    document.getElementById("form-settings-storage").addEventListener("submit", (e) => {
        e.preventDefault();
        if (!settingsData) return;
        const backend = document.getElementById("setting-backend").value;
        const payload = {
            ...settingsData,
            storage_backend: backend
        };
        saveSettings(payload);
    });

    // Settings Webhook Form Submit
    document.getElementById("form-settings-webhook").addEventListener("submit", (e) => {
        e.preventDefault();
        if (!settingsData) return;
        const url = document.getElementById("setting-webhook-url").value;
        const format = document.getElementById("setting-webhook-format").value;
        const tgEnabled = document.getElementById("setting-telegram-enabled").checked;
        const tgToken = document.getElementById("setting-telegram-token").value;
        const tgChatId = document.getElementById("setting-telegram-chat-id").value;

        const headerRows = document.querySelectorAll("#webhook-headers-list .webhook-header-row");
        const headers = {};
        headerRows.forEach(row => {
            const key = row.querySelector(".header-key").value.trim();
            const val = row.querySelector(".header-value").value.trim();
            if (key !== "") {
                headers[key] = val;
            }
        });
        
        const payload = {
            ...settingsData,
            webhook_url: url,
            webhook_format: format,
            webhook_headers: headers,
            telegram_enabled: tgEnabled,
            telegram_token: tgToken,
            telegram_chat_id: tgChatId
        };
        saveSettings(payload);
    });

    // Settings Test Alert Click
    document.getElementById("btn-test-alert").addEventListener("click", async () => {
        try {
            const resp = await fetch("/api/settings/test-alert", {
                method: "POST"
            });
            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || "Failed to trigger test alert");
            }
            showToast("Test alert sent.");
        } catch (err) {
            showToast("Test alert failed: " + err.message, "error");
        }
    });

    // Wizard Setup Form Submit
    document.getElementById("form-wizard").addEventListener("submit", async (e) => {
        e.preventDefault();
        const subnets = document.getElementById("wizard-subnets").value.split(",").map(s => s.trim()).filter(s => s !== "");
        const netflow = parseInt(document.getElementById("wizard-netflow").value, 10);
        const sflow = parseInt(document.getElementById("wizard-sflow").value, 10);
        const backend = document.getElementById("wizard-backend").value;
        
        const payload = {
            port: "8080",
            netflow_port: netflow,
            sflow_port: sflow,
            storage_dir: "/data",
            log_level: "info",
            environment: "production",
            local_subnets: subnets,
            storage_backend: backend,
            first_run_completed: true
        };
        
        try {
            const resp = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || "Setup failed");
            }
            showToast("Setup saved.");
            viewWizard.classList.add("hidden");
            
            settingsData = await resp.json();
            autoRefreshTimer = setInterval(loadData, 5000);
            switchView("dashboard");
        } catch (err) {
            showToast("Setup failed: " + err.message, "error");
        }
    });

    // Initial Load
    async function init() {
        applyStoredShellPreferences();
        const auth = await fetchAuthStatus();
        if (auth.setup_required) {
            showAuthOverlay("setup", "Use at least 10 characters.");
            return;
        }
        if (!auth.authenticated) {
            showAuthOverlay("login");
            return;
        }
        await initAuthenticatedApp();
    }

    async function initAuthenticatedApp() {
        await fetchSettings();
        if (settingsData && settingsData.first_run_completed) {
            const hash = window.location.hash || "#/traffic";
            const viewName = routeViews[hash] || "dashboard";
            switchView(viewName);
            autoRefreshTimer = setInterval(loadData, 5000);
        }
    }
    init();

    // Custom Webhook Headers UI Helpers
    function renderWebhookHeaders(headers) {
        const listContainer = document.getElementById("webhook-headers-list");
        if (!listContainer) return;
        listContainer.innerHTML = "";

        Object.entries(headers).forEach(([key, val]) => {
            appendWebhookHeaderRow(key, val);
        });
    }

    function appendWebhookHeaderRow(key = "", val = "") {
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

        const valueInput = document.createElement("input");
        valueInput.type = "text";
        valueInput.placeholder = "Value";
        valueInput.className = "form-control header-value";
        valueInput.value = val;
        valueInput.style.cssText = "flex: 2; height: 32px; font-size: 0.8rem; padding: 0 0.5rem;";

        const removeButton = document.createElement("button");
        removeButton.type = "button";
        removeButton.className = "btn-secondary btn-remove-header";
        removeButton.textContent = "x";
        removeButton.style.cssText = "height: 32px; width: 32px; padding: 0; line-height: 30px; font-size: 1.1rem; text-align: center; border-radius: 6px; cursor: pointer; flex-shrink: 0;";
        removeButton.addEventListener("click", () => {
            row.remove();
        });

        row.append(keyInput, valueInput, removeButton);
        listContainer.appendChild(row);
    }
});
