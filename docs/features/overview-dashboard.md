# Overview Dashboard

The Overview dashboard is the default landing view for FlowGuard Lite. It combines security posture and network operations signals so a small-network operator can answer:

```text
Is the network healthy right now?
```

## Security Posture Panels

The Overview dashboard includes these security-focused panels:

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

The active time range is selected globally from the application header and applies consistently to Overview and Traffic analysis panels.

## Data Sources

The Overview dashboard uses dedicated bounded APIs:

- `GET /api/security/summary`;
- `GET /api/security/timeline`;
- `GET /api/stats/protocols`;
- `GET /api/stats/top-devices`;
- `GET /api/stats/heatmap`;
- `GET /api/stats/collector-health`;
- `GET /api/traffic/timeseries`.
- `GET /api/traffic/records` for bounded aggregate-row exploration in the Traffic Flow Explorer.

The view does not expose secret values. Settings are used only to show detector and routing configuration presence, such as Suricata path configured/not configured and notification channel configured/not configured.

## Network Stats Panels

The network operations area includes these panels:

- selected time-window summary showing aggregate traffic, packets, flows, and bucket coverage for the global range;
- protocol distribution donut, responsive to the selected time range;
- top 5 known devices by source and destination byte volume;
- bytes/s, packets/s, and flows/s mini sparklines from aggregate buckets;
- subnet/VLAN-style /24 sparklines derived from bounded heatmap cells;
- device activity heatmap by hour of day;
- collector health gauge with current packet, drop, decode error, and queue counters;
- collector drops, decode errors, and queue-depth sparklines backed by a bounded in-memory sample ring.

The Traffic workspace includes a Flow Explorer for analyst-style filtering over retained aggregate rows. This is intentionally not Kibana/Elastic and does not expose raw packet payloads or indefinite raw-flow storage; it searches the bounded `flow_aggregates` rollups by IP, protocol, destination port, and global time range.

## Performance Constraints

The Overview view must remain lightweight:

- no raw flow scans in the browser;
- no unbounded history requests;
- no new charting dependency;
- no heavyweight analytics stack;
- aggregation should use dedicated bounded endpoints.

## Remaining Polish

Remaining polish should focus on visual/manual verification:

- browser screenshot verification on desktop and mobile;
- continued tuning of seeded data so every panel remains populated in development mode.
