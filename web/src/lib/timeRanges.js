import { state } from '../app/state.js';

export const TRAFFIC_RANGE_DEFS = [
    { id: "1h", label: "1h", durationMs: 60 * 60 * 1000, bucket: 60 },
    { id: "6h", label: "6h", durationMs: 6 * 60 * 60 * 1000, bucket: 300 },
    { id: "24h", label: "24h", durationMs: 24 * 60 * 60 * 1000, bucket: 900 },
    { id: "3d", label: "3d", durationMs: 3 * 24 * 60 * 60 * 1000, bucket: 3600 },
    { id: "7d", label: "7d", durationMs: 7 * 24 * 60 * 60 * 1000, bucket: 3600 },
    { id: "15d", label: "15d", durationMs: 15 * 24 * 60 * 60 * 1000, bucket: 6 * 3600 },
    { id: "30d", label: "30d", durationMs: 30 * 24 * 60 * 60 * 1000, bucket: 12 * 3600 },
    { id: "60d", label: "60d", durationMs: 60 * 24 * 60 * 60 * 1000, bucket: 24 * 3600 }
];

const DEFAULT_RETENTION_DAYS = 7;

export function configuredRetentionDays() {
    const raw = Number(state.settingsData?.retention_days || DEFAULT_RETENTION_DAYS);
    return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_RETENTION_DAYS;
}

export function availableTrafficRanges() {
    const retentionDays = configuredRetentionDays();
    const retentionMs = retentionDays * 24 * 60 * 60 * 1000;
    const ranges = TRAFFIC_RANGE_DEFS.filter(def => def.durationMs <= retentionMs);
    const retentionID = `${retentionDays}d`;
    if (retentionDays > 7 && !ranges.some(def => def.id === retentionID)) {
        ranges.push({
            id: retentionID,
            label: retentionID,
            durationMs: retentionMs,
            bucket: bucketForRetentionDays(retentionDays)
        });
    }
    return ranges.sort((a, b) => a.durationMs - b.durationMs);
}

export function normalizeTrafficRange(range = state.activeTrafficRange) {
    const available = availableTrafficRanges();
    if (available.some(def => def.id === range)) return range;
    return (available[available.length - 1] || TRAFFIC_RANGE_DEFS[2]).id;
}

export function setNormalizedTrafficRange(range = state.activeTrafficRange) {
    state.activeTrafficRange = normalizeTrafficRange(range);
    return state.activeTrafficRange;
}

export function trafficRangeConfig() {
    const end = new Date();
    const rangeID = setNormalizedTrafficRange();
    const def = rangeDef(rangeID);
    return {
        start: new Date(end.getTime() - def.durationMs),
        end,
        bucket: def.bucket
    };
}

export function activeRangeDurationMs() {
    const rangeID = setNormalizedTrafficRange();
    return rangeDef(rangeID).durationMs;
}

export function activeRangeBucketSeconds() {
    const rangeID = setNormalizedTrafficRange();
    return rangeDef(rangeID).bucket;
}

export function isDayRange(range = state.activeTrafficRange) {
    return range.endsWith("d");
}

function rangeDef(rangeID) {
    return availableTrafficRanges().find(item => item.id === rangeID) ||
        TRAFFIC_RANGE_DEFS.find(item => item.id === rangeID) ||
        TRAFFIC_RANGE_DEFS[2];
}

function bucketForRetentionDays(days) {
    if (days <= 15) return 6 * 3600;
    if (days <= 30) return 12 * 3600;
    return 24 * 3600;
}
