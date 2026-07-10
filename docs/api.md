# REST API Reference

FlowGuard Lite provides a clean, JSON-based REST API to inspect traffic analytics, query anomalies, manage configurations, and extract firewall rules.

---

## 1. System Endpoints

### GET `/api/health`
Retrieves daemon health status, collector statistics, and queue depth indicators.

*   **Response Status:** `200 OK`
*   **Example Response:**
```json
{
  "status": "OK",
  "healthy": true,
  "environment": "production",
  "timestamp": "2026-07-09T15:28:33Z",
  "version": "0.1.0",
  "collector": {
    "packets_received": 145028,
    "packets_dropped": 0,
    "decode_errors": 0,
    "queue_depth": 14
  }
}
```

### GET `/api/auth/status`
Returns local access-control state.

*   **Response Status:** `200 OK`
*   **Example Response:**
```json
{
  "authenticated": false,
  "setup_required": true
}
```

### POST `/api/auth/setup`
Creates the initial local admin password. This endpoint only works while no admin password hash is configured.

*   **Request Body:**
```json
{
  "password": "minimum 10 characters"
}
```
*   **Response Status:** `200 OK`
*   **Security:** Stores only a PBKDF2-SHA256 password hash and sets an `HttpOnly`, `SameSite=Lax` session cookie.

### POST `/api/auth/login`
Authenticates the local admin password and creates a browser session.

*   **Request Body:**
```json
{
  "password": "admin password"
}
```
*   **Response Status:** `200 OK`
*   **Failure Responses:** `401 Unauthorized` for invalid credentials, `429 Too Many Requests` after repeated failures.

### POST `/api/auth/logout`
Invalidates the current browser session cookie.

*   **Response Status:** `200 OK`

### GET `/api/exporters`
Lists all active exporters (routers/gateways) streaming NetFlow or sFlow telemetry to the daemon.

*   **Response Status:** `200 OK`
*   **Example Response:**
```json
[
  {
    "ip": "192.168.1.1",
    "last_seen": "2026-07-04T14:40:00Z",
    "packet_count": 12402
  }
]
```

---

## 2. Analytics & Devices

### GET `/api/devices`
Lists all discovered local network devices with their hostnames, custom labels, and risk indicators.

*   **Response Status:** `200 OK`
*   **Example Response:**
```json
[
  {
    "ip": "192.168.1.50",
    "mac": "00:11:22:33:44:55",
    "hostname": "NAS-Server",
    "label": "Storage",
    "first_seen": "2026-07-04T10:00:00Z",
    "last_seen": "2026-07-04T14:40:00Z"
  }
]
```

### GET `/api/risk/devices`
Lists internal devices ranked by their calculated threat risk scores (`0 - 100`).

*   **Response Status:** `200 OK`
*   **Example Response:**
```json
[
  {
    "ip": "192.168.1.50",
    "label": "Storage",
    "risk_score": 85,
    "risk_level": "high"
  }
]
```

### Overview dashboard data composition
The default Overview dashboard uses bounded summary and stats endpoints.

*   **Security posture:** `GET /api/security/summary` and `GET /api/security/timeline`.
*   **Network stats:** `GET /api/stats/protocols`, `GET /api/stats/top-devices`, `GET /api/stats/heatmap`, plus `GET /api/traffic/timeseries`.
*   **Flow explorer:** `GET /api/traffic/records` returns retained aggregate rows for bounded analyst filtering. It does not expose raw packets or unbounded raw flow storage.
*   **Security:** Secret settings are not displayed in the dashboard; only configuration presence is shown.

### GET `/api/security/summary`
Returns active alert counts by severity, max risk score, elevated device count, risk distribution, detector coverage, DDoS thresholds, collector counters, top risk devices, and recent high-severity alerts.

### GET `/api/security/timeline`
Returns alert count buckets for the selected time range.

Uses `start`, `end`, and `bucket_seconds` query parameters with the same 7-day maximum range as `/api/traffic/timeseries`.

### GET `/api/stats/protocols`
Returns protocol byte distribution for a bounded range.

Uses the same `start`, `end`, and `limit` query parameters as `/api/top/sources`.

### GET `/api/stats/top-devices`
Returns known devices ranked by combined source and destination byte volume for a bounded range.

Uses the same `start`, `end`, and `limit` query parameters as `/api/top/sources`.

### GET `/api/stats/heatmap`
Returns hour-of-day traffic cells for top devices in a bounded range.

Uses the same `start`, `end`, and `limit` query parameters as `/api/top/sources`; `limit` is capped at 20 devices.

### GET `/api/stats/collector-health`
Returns bounded in-memory collector health samples for Overview sparklines.

*   **Query Parameters:**
    *   `limit` (Optional, integer): Defaults to `120`; capped at `240`.
*   **Example Response:**
```json
[
  {
    "timestamp": "2026-07-08T15:40:00Z",
    "packets_received": 145028,
    "packets_dropped": 0,
    "decode_errors": 0,
    "queue_depth": 14
  }
]
```

### GET `/api/traffic/timeseries`
Returns bounded aggregate traffic counters for network charts.

*   **Query Parameters:**
    *   `start` (Optional, RFC3339): Defaults to one hour before `end`.
    *   `end` (Optional, RFC3339): Defaults to now.
    *   `bucket_seconds` (Optional): One of `60`, `300`, `900`, or `3600`. Defaults to `300`.
*   **Limits:** The maximum query range is 7 days.
*   **Response Status:** `200 OK`
*   **Example Response:**
```json
[
  {
    "timestamp": "2026-07-04T14:00:00Z",
    "bytes": 15432000,
    "packets": 12402,
    "flows": 384
  }
]
```

### GET `/api/traffic/records`
Returns retained aggregate rows for analyst search/filter workflows. Each row is a bounded rollup from `flow_aggregates`, not a raw packet or indefinite raw flow record.

*   **Query Parameters:**
    *   `start` (Optional, RFC3339): Defaults to one hour before `end`.
    *   `end` (Optional, RFC3339): Defaults to now.
    *   `limit` (Optional, integer): Defaults to `10`; capped by API pagination.
    *   `q` (Optional, string): Case-insensitive match against source or destination IP; capped at 128 characters.
    *   `protocol` (Optional, integer): IP protocol number, `0`-`255`.
    *   `dst_port` (Optional, integer): Destination port, `0`-`65535`.
*   **Limits:** The maximum query range is 7 days.
*   **Example Response:**
```json
[
  {
    "timestamp": "2026-07-04T14:00:00Z",
    "src_ip": "192.168.30.150",
    "dst_ip": "8.8.8.8",
    "dst_port": 53,
    "protocol": 17,
    "bytes": 1200,
    "packets": 12,
    "flows": 2
  }
]
```

### GET `/api/top/sources`
Returns the top source IP addresses by byte volume for a bounded time range.

*   **Query Parameters:**
    *   `start` (Optional, RFC3339): Defaults to one hour before `end`.
    *   `end` (Optional, RFC3339): Defaults to now.
    *   `limit` (Optional, integer): Defaults to `10`.
*   **Limits:** The maximum query range is 7 days.

### GET `/api/top/destinations`
Returns the top destination IP addresses by byte volume for a bounded time range.

Uses the same query parameters and 7-day maximum range as `/api/top/sources`.

### GET `/api/top/ports`
Returns the top destination ports by byte volume for a bounded time range.

Uses the same query parameters and 7-day maximum range as `/api/top/sources`.

### GET `/api/top/protocols`
Returns the top transport protocol numbers by byte volume for a bounded time range.

Uses the same query parameters and 7-day maximum range as `/api/top/sources`.

*   **Example Response:**
```json
[
  {
    "key": "6",
    "bytes": 328780000,
    "packets": 84200,
    "flows": 1260
  }
]
```

---

## 3. Anomalies & Audit Logs

### GET `/api/anomalies`
Lists all flagged anomalies, baseline breaches, or volumetric DDoS detections.

*   **Query Parameters:**
    *   `limit` (Optional, integer): Default `50`. Limit results returned.
*   **Response Status:** `200 OK`
*   **Example Response:**
```json
[
  {
    "id": 42,
    "ip": "192.168.1.50",
    "destination_ip": "192.168.1.25",
    "type": "NEW_INTERNAL_COMMUNICATION",
    "description": "what happened: device contacted internal peer 192.168.1.25 after its east-west peer set was learned; why unusual: this local-to-local communication pattern was not present in the learned internal peer baseline...",
    "severity": "medium",
    "status": "active",
    "created_at": "2026-07-04T14:38:00Z",
    "updated_at": "2026-07-04T14:38:00Z"
  }
]
```

`destination_ip` is omitted or empty when a detector does not have one specific destination. When present, `ip`/`subnet` policies can match either the source `ip` or the structured `destination_ip`.

### GET `/api/audit-logs`
Lists security audit entries documenting configuration modifications and threat triage responses.

*   **Response Status:** `200 OK`
*   **Example Response:**
```json
[
  {
    "timestamp": "2026-07-04T14:30:00Z",
    "action": "settings_updated",
    "details": "Local subnets range modified to: 192.168.1.0/24"
  }
]
```

---

## 4. Settings Configuration

### GET `/api/settings`
Returns the active configuration schema.

*   **Response Status:** `200 OK`
*   **Example Response:**
```json
{
  "port": "8080",
  "netflow_port": 2055,
  "sflow_port": 6343,
  "capture_interface": "",
  "capture_bpf_filter": "ip or ip6",
  "capture_promiscuous": false,
  "storage_backend": "sqlite",
  "local_subnets": [
    "192.168.1.0/24"
  ],
  "webhook_url": "https://hooks.slack.com/...",
  "webhook_format": "slack",
  "webhook_headers": {
    "Authorization": "******"
  },
  "first_run_completed": true,
  "retention_days": 7,
  "ddos_threshold_pps": 5000,
  "ddos_threshold_bps": 10485760,
  "syn_flood_threshold_pps": 1000,
  "udp_flood_threshold_pps": 3000,
  "icmp_flood_threshold_pps": 500,
  "suricata_eve_path": "/var/log/suricata/eve.json",
  "admin_password": ""
}
```

### POST `/api/settings`
Updates the configuration keys and saves them to `config.yaml` on disk.

*   **Request Body JSON Schema:** (Same as GET response)
*   **Response Status:** `200 OK` (Returns the updated config)
*   **Passive capture validation:** `capture_interface` is optional and enables capture when non-empty. An enabled interface requires a non-empty `capture_bpf_filter`; interface and filter values are length-bounded and reject null/control line breaks. Capture changes require a daemon restart.

---

## 5. Policy Configuration

### GET `/api/policies`
Lists all active policies.

*   **Response Status:** `200 OK`
*   **Example Response:**
```json
[
  {
    "id": 1,
    "name": "Silence Port Scans",
    "scope": "alert_type",
    "target": "port_scan",
    "severity_threshold": "medium",
    "suppressed": true,
    "cooldown_seconds": 60,
    "quiet_hours_start": "22:00",
    "quiet_hours_end": "06:00",
    "notification_channels": ["slack", "telegram"],
    "created_at": "2026-07-05T14:40:00Z",
    "updated_at": "2026-07-05T14:40:00Z"
  }
]
```

### POST `/api/policies`
Creates a new policy.

*   **Request Body JSON:**
```json
{
  "name": "Silence Port Scans",
  "scope": "alert_type",
  "target": "port_scan",
  "severity_threshold": "medium",
  "suppressed": true,
  "cooldown_seconds": 60,
  "quiet_hours_start": "22:00",
  "quiet_hours_end": "06:00",
  "notification_channels": ["slack", "telegram"]
}
```
*   **Response Status:** `200 OK` (Returns the created policy object with populated `id`, `created_at` and `updated_at`)

To suppress all anomaly types for one verified noisy device, create an exact-IP policy:

```json
{
  "name": "Authorized infrastructure scanner",
  "scope": "ip",
  "target": "192.168.10.25",
  "severity_threshold": "",
  "suppressed": true,
  "cooldown_seconds": 0,
  "quiet_hours_start": "",
  "quiet_hours_end": "",
  "notification_channels": []
}
```

Matching anomalies remain persisted with status `silenced`. Policy precedence is `ip` > `subnet` > `alert_type` > `global`; the newest policy wins when scopes have equal precedence. Equivalent textual forms of the same IPv6 address are treated as one address.

To suppress a verified benign destination, use the same `ip` scope with the destination address as `target`. The policy matches anomalies whose structured `destination_ip` equals that address while leaving unrelated destinations active.

### PUT `/api/policies/{id}`
Updates an existing policy.

*   **Request Body JSON:** (Same as POST payload, optionally including fields to edit)
*   **Response Status:** `200 OK` (Returns the updated policy object)
*   **Failure Response:** `400 Bad Request` if payload is invalid (e.g. invalid quiet hours format, missing name, or invalid target format).

### DELETE `/api/policies/{id}`
Deletes a policy by its ID.

*   **Response Status:** `200 OK`
*   **Example Response:**
```json
{
  "status": "deleted"
}
```
