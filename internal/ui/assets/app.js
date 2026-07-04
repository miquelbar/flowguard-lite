// FlowGuard Lite Dashboard Logic Engine
document.addEventListener("DOMContentLoaded", () => {
    let activeView = "dashboard";
    let activeTab = "sources";
    let activeTriageFilter = "all";
    let autoRefreshTimer = null;
    
    // In-memory data states
    let talkersData = [];
    let exportersData = [];
    let devicesData = [];
    let anomaliesData = [];
    let riskDevicesData = [];
    let selectedDeviceIP = null;

    // Navigation elements
    const navDashboard = document.getElementById("nav-dashboard");
    const navDevices = document.getElementById("nav-devices");
    const navAnomalies = document.getElementById("nav-anomalies");
    
    const viewDashboard = document.getElementById("view-dashboard");
    const viewDevices = document.getElementById("view-devices");
    const viewAnomalies = document.getElementById("view-anomalies");

    // Elements
    const btnRefresh = document.getElementById("btn-refresh");
    const inputSearch = document.getElementById("input-search");
    const inputDeviceSearch = document.getElementById("input-device-search");
    
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
        } catch (err) {
            console.error("Error fetching health: ", err);
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
            const resp = await fetch(`/api/top/${activeTab}?limit=50`);
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
        } catch (err) {
            console.error("Error fetching anomalies: ", err);
        }
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
            tblThreatRisk.innerHTML = `<tr><td colspan="3" class="text-center text-muted">All devices functioning at Low Risk.</td></tr>`;
            return;
        }

        tblThreatRisk.innerHTML = riskDevicesData.map(dev => {
            const badgeClass = dev.risk_level === "high" ? "risk-badge-high" : (dev.risk_level === "medium" ? "risk-badge-medium" : "risk-badge-low");
            return `
                <tr style="cursor: pointer;" class="threat-device-row" data-ip="${dev.ip}">
                    <td class="font-semibold">${dev.ip} ${dev.label ? `<span style="font-size:0.75rem; font-weight:normal;" class="badge badge-label">${dev.label}</span>` : ''}</td>
                    <td>
                        <div style="display:flex; align-items:center; gap:0.5rem;">
                            <span class="risk-badge ${badgeClass}" style="padding: 0.15rem 0.4rem; font-size: 0.75rem;">${dev.risk_score}</span>
                        </div>
                    </td>
                    <td class="text-right text-muted" style="text-transform: capitalize;">${dev.risk_level} Risk</td>
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
                    <td>${dev.label ? `<span class="badge badge-label">${dev.label}</span>` : "<span class="text-muted">-</span>"}</td>
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

            showToast(`Label for ${selectedDeviceIP} updated successfully!`);
            await fetchDevices();
            const dev = devicesData.find(d => d.ip === selectedDeviceIP);
            if (dev) {
                inputDetailLabel.value = dev.label || "";
            }
        } catch (err) {
            showToast(err.message, "error");
        }
    });

    // Render Anomalies to table
    function renderAnomalies() {
        const filtered = anomaliesData.filter(anom => {
            if (activeTriageFilter === "all") return true;
            return anom.status === activeTriageFilter;
        });

        if (filtered.length === 0) {
            tblAnomalies.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No anomalies match selection filter.</td></tr>`;
            return;
        }

        tblAnomalies.innerHTML = filtered.map(anom => {
            const badgeClass = anom.severity === "high" ? "badge-high" : (anom.severity === "medium" ? "badge-medium" : "badge-low");
            const statusClass = `status-${anom.status}`;
            
            // Build triage buttons depending on current status
            let buttonsHtml = "";
            if (anom.status === "active") {
                buttonsHtml = `
                    <button class="btn-triage btn-ack" data-id="${anom.id}" data-action="acknowledged">Acknowledge</button>
                    <button class="btn-triage btn-silence" data-id="${anom.id}" data-action="silenced">Silence</button>
                `;
            } else {
                buttonsHtml = `
                    <button class="btn-triage btn-reactivate" data-id="${anom.id}" data-action="active">Reactivate</button>
                `;
            }

            return `
                <tr>
                    <td class="font-semibold">${anom.ip}</td>
                    <td><span class="badge ${badgeClass}">${anom.type}</span></td>
                    <td style="text-transform: capitalize;">${anom.severity}</td>
                    <td>${anom.description}</td>
                    <td>${formatTime(anom.created_at)}</td>
                    <td><span class="${statusClass}">${anom.status}</span></td>
                    <td class="triage-actions">${buttonsHtml}</td>
                </tr>
            `;
        }).join('');

        // Attach triage buttons click listeners
        tblAnomalies.querySelectorAll(".btn-triage").forEach(btn => {
            btn.addEventListener("click", async (e) => {
                const id = e.target.getAttribute("data-id");
                const action = e.target.getAttribute("data-action");
                await updateAnomalyStatus(id, action);
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

            if (!resp.ok) throw new Error("Failed to update alert review status");

            showToast(`Alert status successfully updated to ${newStatus}!`);
            await Promise.all([
                fetchAnomalies(),
                fetchThreatRisk()
            ]);
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    // Perform full page data fetch
    async function loadData() {
        // Fetch threat risk ranks unconditionally as they affect indicators and badges across multiple views
        await fetchThreatRisk();

        if (activeView === "dashboard") {
            await Promise.all([
                fetchHealth(),
                fetchExporters(),
                fetchTopTalkers()
            ]);
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
        }
    }

    // Switch between SPA views
    function switchView(viewName) {
        activeView = viewName;
        
        // Remove active class from all nav links
        navDashboard.classList.remove("active");
        navDevices.classList.remove("active");
        navAnomalies.classList.remove("active");

        // Hide all views
        viewDashboard.classList.remove("active");
        viewDevices.classList.remove("active");
        viewAnomalies.classList.remove("active");

        if (viewName === "dashboard") {
            navDashboard.classList.add("active");
            viewDashboard.classList.add("active");
        } else if (viewName === "devices") {
            navDevices.classList.add("active");
            viewDevices.classList.add("active");
        } else if (viewName === "anomalies") {
            navAnomalies.classList.add("active");
            viewAnomalies.classList.add("active");
        }
        
        loadData();
    }

    // Navigation Button Listeners
    navDashboard.addEventListener("click", () => switchView("dashboard"));
    navDevices.addEventListener("click", () => switchView("devices"));
    navAnomalies.addEventListener("click", () => switchView("anomalies"));

    // Handle Manual Refresh
    btnRefresh.addEventListener("click", () => {
        loadData();
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

    // Handle triage status filter buttons
    triageFilterButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            triageFilterButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeTriageFilter = e.target.getAttribute("data-status");
            renderAnomalies();
        });
    });

    // Initial Load & Auto-Refresh Setup (every 5 seconds)
    loadData();
    autoRefreshTimer = setInterval(loadData, 5000);
});
