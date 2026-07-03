// FlowGuard Lite Dashboard Logic Engine
document.addEventListener("DOMContentLoaded", () => {
    let activeTab = "sources";
    let autoRefreshTimer = null;
    let talkersData = [];
    let exportersData = [];

    // Elements
    const btnRefresh = document.getElementById("btn-refresh");
    const inputSearch = document.getElementById("input-search");
    const valPackets = document.getElementById("val-packets");
    const valDrops = document.getElementById("val-drops");
    const valErrors = document.getElementById("val-errors");
    const valQueue = document.getElementById("val-queue");
    const tblExporters = document.getElementById("tbl-exporters").querySelector("tbody");
    const tblTopTalkers = document.getElementById("tbl-top-talkers").querySelector("tbody");
    const tabButtons = document.querySelectorAll(".tab-btn");

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
        return date.toLocaleTimeString();
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

    // Render Top Talkers to table with progress bars
    function renderTopTalkers() {
        const query = inputSearch.value.trim().toLowerCase();
        
        // Apply search filter locally
        const filtered = talkersData.filter(item => {
            return item.key.toLowerCase().includes(query);
        });

        if (filtered.length === 0) {
            tblTopTalkers.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No records match the active filters.</td></tr>`;
            return;
        }

        // Find max byte volume for progress bar calculation
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

    // Perform full page data fetch
    async function loadData() {
        await Promise.all([
            fetchHealth(),
            fetchExporters(),
            fetchTopTalkers()
        ]);
    }

    // Handle Manual Refresh
    btnRefresh.addEventListener("click", () => {
        loadData();
    });

    // Handle Search input filtering
    inputSearch.addEventListener("input", () => {
        renderTopTalkers();
    });

    // Handle Tab buttons click
    tabButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            tabButtons.forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            activeTab = e.target.getAttribute("data-tab");
            
            // Reload Top Talkers for the new tab selection
            fetchTopTalkers();
        });
    });

    // Initial Load & Auto-Refresh Setup (every 5 seconds)
    loadData();
    autoRefreshTimer = setInterval(loadData, 5000);
});
