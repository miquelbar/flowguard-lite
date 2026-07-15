import { state } from '../app/state.js';
import * as api from '../lib/api.js';
import { renderOverviewView } from '../features/overview/overviewView.js';
import { renderTrafficView } from '../features/traffic/trafficView.js';
import { renderDevicesView } from '../features/devices/devicesView.js';
import { renderAlertsView } from '../features/alerts/alertsView.js';
import { renderPoliciesView } from '../features/policies/policiesView.js';
import { renderNotificationsView } from '../features/notifications/notificationsView.js';
import { renderAuditView } from '../features/audit/auditView.js';
import { renderSettingsView } from '../features/settings/settingsView.js';
import { enhanceSortableTables } from '../lib/tableSort.js';
import { setNormalizedTrafficRange, trafficRangeConfig } from '../lib/timeRanges.js';
import { syncGlobalRangeButtons } from '../services/globalRangeControls.js';
import { updateStatusIndicator } from '../services/statusIndicator.js';

async function settle(label, promise, fallback) {
    try {
        return { value: await promise, error: null };
    } catch (err) {
        console.error(`${label} load failed: `, err);
        return { value: fallback, error: err.message || "query failed" };
    }
}

async function settleOverview(label, promise, fallback) {
    return await settle(`Overview ${label}`, promise, fallback);
}

async function loadShellStatus() {
    let healthError = null;
    const [health, threatRisk] = await Promise.all([
        api.fetchHealth().catch(err => {
            healthError = err.message || "API health check failed";
            throw err;
        }),
        api.fetchThreatRisk().catch(err => {
            console.error("Risk check failed: ", err);
            return [];
        })
    ]).catch(err => {
        console.error("Health check failed: ", err);
        return [{ healthy: false, error_message: healthError || "API Offline" }, []];
    });

    updateStatusIndicator(health);
    state.healthData = health;
    state.riskDevicesData = threatRisk || [];
}

async function loadOverviewView() {
    const range = trafficRangeConfig();
    const overviewRequests = {
        summary: settleOverview("security summary", api.fetchSecuritySummary(), null),
        timeline: settleOverview("security timeline", api.fetchSecurityTimeline(range), []),
        protocols: settleOverview("protocol stats", api.fetchStatsProtocols(range), []),
        topDevices: settleOverview("top devices stats", api.fetchStatsTopDevices(range), []),
        heatmap: settleOverview("device heatmap", api.fetchStatsHeatmap(range), []),
        collectorHealth: settleOverview("collector health", api.fetchStatsCollectorHealth(), []),
        trafficSeries: settleOverview("traffic time-series", api.fetchTrafficTimeSeries(range), [])
    };
    const results = Object.fromEntries(
        await Promise.all(Object.entries(overviewRequests).map(async ([key, promise]) => [key, await promise]))
    );
    const overviewErrors = {};
    for (const [key, result] of Object.entries(results)) {
        if (result.error) overviewErrors[key] = result.error;
    }
    state.overviewErrors = overviewErrors;
    state.securitySummaryData = results.summary.value || null;
    state.securityTimelineData = results.timeline.value || [];
    state.overviewProtocolsData = results.protocols.value || [];
    state.overviewTopDevicesData = results.topDevices.value || [];
    state.overviewHeatmapData = results.heatmap.value || [];
    state.overviewCollectorHealthData = results.collectorHealth.value || [];
    state.trafficSeriesData = results.trafficSeries.value || [];
    state.riskDevicesData = results.summary.value?.top_risk_devices || state.riskDevicesData || [];
    state.anomaliesData = results.summary.value?.recent_high_alerts || [];
    renderOverviewView();
}

async function loadTrafficView() {
	const range = trafficRangeConfig();
	const talkersRequest = state.activeTab === "devices"
		? api.fetchStatsTopDevices(range, "50")
		: api.fetchTopTalkers(state.activeTab, range);
    const trafficRequests = {
        topTalkers: settle("traffic top talkers", talkersRequest, []),
        devices: settle("traffic devices", api.fetchDevices(), []),
        anomalies: settle("traffic anomalies", api.fetchAnomalies(), []),
        trafficSeries: settle("traffic time-series", api.fetchTrafficTimeSeries(range), [])
    };
    const results = Object.fromEntries(
        await Promise.all(Object.entries(trafficRequests).map(async ([key, promise]) => [key, await promise]))
    );
    const trafficErrors = {};
    for (const [key, result] of Object.entries(results)) {
        if (result.error) trafficErrors[key] = result.error;
    }
    state.trafficErrors = trafficErrors;
    state.talkersData = results.topTalkers.value;
    state.devicesData = results.devices.value;
    state.anomaliesData = results.anomalies.value;
    state.trafficSeriesData = results.trafficSeries.value;

    const recordsRes = await settle("traffic records", api.fetchTrafficRecords(range, state.trafficRecordFilters), []);
    state.trafficRecordsData = recordsRes.value;
    if (recordsRes.error) {
        state.trafficErrors.trafficRecords = recordsRes.error;
    }

    renderTrafficView();
}

async function loadNotificationsView() {
    const notificationRequests = {
        rules: settle("notification rules", api.fetchNotificationRules(), []),
        logs: settle("notification logs", api.fetchNotificationLogs(), [])
    };
    const results = Object.fromEntries(
        await Promise.all(Object.entries(notificationRequests).map(async ([key, promise]) => [key, await promise]))
    );
    state.notificationRulesData = results.rules.value;
    state.notificationRulesError = results.rules.error;
    state.notificationLogsData = results.logs.value;
    state.notificationLogsError = results.logs.error;
    renderNotificationsView();
}

async function loadSettingsView(isManualRefresh) {
    if (!state.settingsData || isManualRefresh) {
        const res = await settle("settings", api.fetchSettings(), null);
        state.settingsData = res.value;
        state.settingsError = res.error;
        renderSettingsView();
    }
}

export async function loadData(isManualRefresh = false) {
    try {
        if ((state.activeView === "overview" || state.activeView === "dashboard") && !state.settingsData) {
            const res = await settle("settings", api.fetchSettings(), null);
            state.settingsData = res.value;
            state.settingsError = res.error;
        }
        setNormalizedTrafficRange();
        syncGlobalRangeButtons(loadData);

        await loadShellStatus();

        if (state.activeView === "overview") {
            await loadOverviewView();
        } else if (state.activeView === "dashboard") {
            await loadTrafficView();
        } else if (state.activeView === "devices") {
            const res = await settle("devices", api.fetchDevices(), []);
            state.devicesData = res.value;
            state.devicesError = res.error;
            renderDevicesView();
        } else if (state.activeView === "anomalies") {
            const results = Object.fromEntries(
                await Promise.all([
                    ["anomalies", settle("anomalies", api.fetchAnomalies(), [])],
                    ["devices", settle("alert devices", api.fetchDevices(), [])]
                ].map(async ([key, promise]) => [key, await promise]))
            );
            state.anomaliesData = results.anomalies.value;
            state.anomaliesError = results.anomalies.error;
            state.devicesData = results.devices.value;
            state.devicesError = results.devices.error;
            renderAlertsView();
        } else if (state.activeView === "policies") {
            const res = await settle("policies", api.fetchPolicies(), []);
            state.policiesData = res.value;
            state.policiesError = res.error;
            renderPoliciesView();
        } else if (state.activeView === "notifications") {
            await loadNotificationsView();
        } else if (state.activeView === "audit") {
            const res = await settle("audit logs", api.fetchAuditLogs(), []);
            state.auditLogsData = res.value;
            state.auditLogsError = res.error;
            renderAuditView();
        } else if (state.activeView === "settings") {
            await loadSettingsView(isManualRefresh);
        }
        enhanceSortableTables();
    } catch (err) {
        console.error("Data load failed: ", err);
    }
}
