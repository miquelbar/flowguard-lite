# Overview Dashboard

The Overview dashboard is the default landing view for FlowGuard Lite. It combines security posture and network operations signals so a small-network operator can answer:

```text
Is the network healthy right now?
```

## Security Posture Panels

The first M26 implementation adds these security-focused panels:

- active alerts count;
- max device risk score;
- elevated-risk device count;
- high/critical active alert count;
- active alerts grouped by severity;
- recent alert clusters on an hourly attack timeline;
- top local IPs with active alert evidence;
- recent high-severity alerts with links into alert detail and IP profile workflows;
- device risk distribution;
- detection coverage summary.

## Data Sources

The Overview dashboard uses dedicated bounded APIs for M26.2/M26.3:

- `GET /api/security/summary`;
- `GET /api/security/timeline`;
- `GET /api/stats/protocols`;
- `GET /api/stats/top-devices`;
- `GET /api/stats/heatmap`;
- `GET /api/stats/collector-health`;
- `GET /api/traffic/timeseries`.

The view does not expose secret values. Settings are used only to show detector and routing configuration presence, such as Suricata path configured/not configured and notification channel configured/not configured.

## Network Stats Panels

M26.2 adds these network operations panels:

- protocol distribution donut, responsive to the selected time range;
- top 5 known devices by source and destination byte volume;
- bytes/s, packets/s, and flows/s mini sparklines from aggregate buckets;
- subnet/VLAN-style /24 sparklines derived from bounded heatmap cells;
- device activity heatmap by hour of day;
- collector health gauge with current packet, drop, decode error, and queue counters;
- collector drops, decode errors, and queue-depth sparklines backed by a bounded in-memory sample ring.

## Performance Constraints

The Overview view must remain lightweight:

- no raw flow scans in the browser;
- no unbounded history requests;
- no new charting dependency;
- no heavyweight analytics stack;
- aggregation should move to dedicated bounded endpoints in M26.3.

## Remaining M26 Work

Remaining polish should focus on visual/manual verification:

- browser screenshot verification on desktop and mobile;
- continued tuning of seeded data so every panel remains populated in development mode.
