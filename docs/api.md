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
  "status": "healthy",
  "version": "1.0.0",
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
    "id": "anom_01",
    "timestamp": "2026-07-04T14:38:00Z",
    "device_ip": "192.168.1.50",
    "type": "outbound_volume",
    "details": "Outgoing traffic of 5.2 MB/s exceeded baseline mean by 5.4 std deviations.",
    "severity": "high",
    "status": "active"
  }
]
```

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
