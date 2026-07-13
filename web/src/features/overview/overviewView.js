import { state } from '../../app/state.js';
import { formatNumber } from '../../lib/format.js';
import { setText } from './overviewSupport.js';
import { renderAttackTimeline } from './overviewTimeline.js';
import {
    renderCollectorHealth,
    renderDetectionCoverage,
    renderDeviceHeatmap,
    renderProtocolDonut,
    renderRateSparklines,
    renderRecentHighSeverity,
    renderRiskDistribution,
    renderSeveritySummary,
    renderSubnetSparklines,
    renderTopDevicesBars,
    renderTopThreatActors,
    renderWindowSummary
} from './overviewPanels.js';

export function renderOverviewView() {
    syncOverviewRangeButtons();
    const summary = state.securitySummaryData || {};
    const counts = summary.active_alerts_by_severity || {};

    setText("overview-max-risk", formatNumber(summary.max_risk_score || 0));
    setText("overview-elevated-devices", formatNumber(summary.elevated_risk_devices || 0));

    renderWindowSummary();
    renderSeveritySummary(counts);
    renderAttackTimeline();
    renderTopThreatActors(summary.top_risk_devices || []);
    renderRecentHighSeverity(summary.recent_high_alerts || []);
    renderRiskDistribution(summary.risk_distribution || {});
    renderDetectionCoverage(summary);
    renderProtocolDonut();
    renderTopDevicesBars();
    renderRateSparklines();
    renderSubnetSparklines();
    renderDeviceHeatmap();
    renderCollectorHealth(summary.collector || null);
}

function syncOverviewRangeButtons() {
    document.querySelectorAll(".overview-range-btn").forEach(btn => {
        btn.classList.toggle("active", btn.getAttribute("data-range") === state.activeTrafficRange);
    });
}

export function bindOverviewEvents(onReload) {
    document.querySelectorAll(".overview-range-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            document.querySelectorAll(".overview-range-btn").forEach(b => b.classList.remove("active"));
            e.currentTarget.classList.add("active");
            state.activeTrafficRange = e.currentTarget.getAttribute("data-range");
            if (onReload) onReload();
        });
    });
}
