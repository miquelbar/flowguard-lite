# Operator Workflows and UI Information Architecture

FlowGuard Lite is not a generic SIEM. The interface must help small-network operators answer practical investigation questions quickly, without requiring them to understand raw NetFlow, sFlow, or Suricata internals.

This document defines the target UI information architecture for the operator experience.

---

## Design Principle

The user should be able to move from a network symptom to an affected IP, understand why that IP is risky, see which policies apply, and decide which alert or response action is appropriate.

The UI must prioritize:

- traffic health over decorative dashboards;
- IP-centered investigation over isolated tables;
- explainable risk over opaque scores;
- Bounded time ranges over unbounded searches;
- Explicit notifications and recommendations over automatic blocking.

---

## Primary Navigation

### Overview

Operator question:

```text
Is the network healthy right now?
```

Expected content:

- traffic volume over time;
- packet and flow rate over time;
- current risk summary;
- active exporters and freshness;
- recent anomalies overlaid on network activity;
- highest-risk IPs;
- degraded collector conditions such as drops, decode errors, or queue pressure.

### Network

Operator question:

```text
What changed in traffic patterns?
```

Expected content:

- time-series charts for bytes, packets, and flows;
- top sources, destinations, ports, and protocols;
- subnet/VLAN summaries;
- time range controls for `1h`, `6h`, `24h`, and `7d`;
- drill-down links into IP Profiles.

Implementation constraints:

- use bounded aggregate queries;
- never load unbounded history into the browser;
- use existing SQLite/DuckDB aggregate storage;
- avoid heavyweight analytics infrastructure.

### IP Profiles

Operator question:

```text
What is this IP doing, and why should I care?
```

Expected content for each IP:

- identity: IP, hostname, label, subnet/VLAN, first seen, last seen;
- traffic timeline;
- top peers;
- top destination ports;
- baseline versus current behavior;
- active and historical alerts;
- Suricata evidence when available;
- Risk Index breakdown;
- policies and suppressions applying to the IP;
- firewall templates and recommended next actions.

Required drill-down entry points:

- Risk Ranking row;
- Top Talkers row;
- Device Inventory row;
- Alert row;
- Audit/policy references where applicable.

### Alerts

Operator question:

```text
Which events need review, and what evidence supports them?
```

Expected content:

- active, acknowledged, and silenced alerts;
- severity and type filters;
- search by IP, type, and description;
- expandable evidence drawer;
- link to the affected IP Profile;
- clear triage actions;
- explanation of baseline deviation where applicable.

### Policies

Operator question:

```text
Which rules affect this IP, subnet, alert type, or severity?
```

Expected content:

- global policies;
- subnet policies;
- IP policies;
- alert-type policies;
- suppression and silence rules;
- severity thresholds;
- quiet hours;
- cooldown and deduplication;
- policy precedence preview;
- audit trail for changes.

Policies must not trigger automatic destructive blocking.

### Notifications

Operator question:

```text
Which alerts will be sent, and to which channel?
```

Expected content:

- channel credentials and health;
- notification routing rules;
- route by severity, alert type, IP, subnet, or policy;
- cooldown and deduplication;
- per-rule test alert;
- delivery history: sent, suppressed, deduplicated, failed.

Credentials belong in Notifications/Integrations; routing behavior belongs in notification rules.

### Audit

Operator question:

```text
Who changed what, and what actions were taken?
```

Expected content:

- settings changes;
- policy changes;
- alert triage changes;
- notification test sends;
- authentication events;
- search and pagination over bounded results.

### Settings

Operator question:

```text
How is this FlowGuard node configured?
```

Settings must be split by responsibility:

- Access;
- Network Interfaces and Subnets;
- Collectors;
- Storage and Retention;
- Detection Thresholds;
- Policies;
- Notifications;
- Integrations;
- System.

Settings must clearly show:

- restart-required changes;
- validation errors;
- masked secrets;
- current runtime state where relevant.

---

## Existing Gaps to Reconcile

The development roadmap already includes several capabilities that are not yet properly represented in the UI:

- device detail links to flows, anomalies, and Suricata evidence;
- device detail view with a dynamic flow timeline;
- DDoS dashboard overview cards;
- Suricata evidence in device detail;
- thresholds configuration UI;
- risk score explanation and evidence.

These gaps must be treated as development debt, not as optional polish.

---

## Risk Index UI Requirements

The Risk Index must be explainable wherever it appears.

Current scoring behavior is defined in detail in the canonical [Experimental Threat Risk Scoring](anomaly-detection.md#10-experimental-threat-risk-scoring) section:

- `high` alert base weight: 40;
- `medium` alert base weight: 20;
- `low` alert base weight: 10;
- score decays linearly across 24 hours with a 15% floor;
- Suricata plus flow anomaly correlation within 1 hour adds `+20` booster;
- score caps at 100;
- `medium` classification threshold starts from 30;
- `high` classification threshold starts from 70.

UI requirements:

- show score components;
- show evidence age and decay;
- show correlation boost when present;
- link each component to the contributing alert or evidence;
- explain the level in plain language.

Example:

```text
Medium risk because a high DDoS alert 30 minutes ago contributes 39/40 after decay. No Suricata-flow correlation was found, so no +20 boost was applied.
```

---

## Visual Direction

The UI is designed to feel like a simple network visibility page for homelabs and small self-hosted networks.

Avoid:

- marketing-style hero layouts;
- decorative glows;
- glassmorphism;
- oversized cards;
- generic SaaS gradient styling;
- vague "insight" panels without operational value.

Prefer:

- dense but readable tables;
- clear drill-down paths;
- compact charts;
- restrained surfaces;
- muted blue/orange dark mode;
- orange for warning/attention;
- red only for critical states;
- labels and copy that explain what the operator can do next.

---

## Implementation Order

1. Access control and deployment safety.
2. Network overview with time-series charts.
3. IP profile workspace.
4. Policies.
5. Notification routing rules.
6. Risk index explainability.
7. Settings rebuild.
8. Usability improvements.

Access control should happen before broader UI rollout because configuration, alerts, policies, and internal network metadata are sensitive.
