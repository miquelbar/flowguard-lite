# External Integrations & Webhooks

FlowGuard Lite interfaces with external security tools and chat programs to provide real-time alerting and responses.

---

## 1. Suricata IDS Alert Ingestion

FlowGuard Lite can ingest alerts from a Suricata intrusion detection system:

*   **Log Location:** Configure the agent to point to your Suricata `eve.json` output path.
*   **Mechanism:** Uses a lightweight tailing library to follow the log in real-time.
*   **Correlation:** Matches Suricata threat categories (e.g. *Trojan activity*, *Command and Control*) with NetFlow timestamps to boost device risk scores.

---

## 2. Outbound Alert Webhooks

When an anomaly is detected, FlowGuard Lite dispatches notifications.

### Supported Webhook Formats

#### Slack & Discord Compatible
Generates structured Slack block attachments:
```json
{
  "text": "🛡️ *FlowGuard Lite Alert*",
  "attachments": [
    {
      "color": "#ef4444",
      "fields": [
        { "title": "Device", "value": "192.168.1.50", "short": true },
        { "title": "Risk Level", "value": "High Risk", "short": true },
        { "title": "Description", "value": "Suspicious outbound traffic spike.", "short": false }
      ]
    }
  ]
}
```

#### Telegram Bot API
Dispatches HTML-formatted message blocks to your configured Telegram channel:
```json
{
  "chat_id": "@my_channel",
  "text": "🛡️ <b>FlowGuard Lite Alert</b>\nDevice: 192.168.1.50\nRisk Level: High Risk\nSuspicious outbound traffic spike.",
  "parse_mode": "HTML"
}
```

#### Generic JSON Payload
Sends a raw JSON object detailing the event for third-party scripts.

### Custom Webhook Headers

Outbound webhook requests can include custom authentication headers configured from the Settings UI, `config.yaml`, or the `FLOWGUARD_WEBHOOK_HEADERS` JSON environment override. Common examples are `Authorization: Bearer ...` or `X-Webhook-Token: ...`.

Header values are treated as secrets in runtime logging. FlowGuard Lite logs only whether a webhook is configured and how many custom headers are active.

---

## 3. Firewall Block Exporters

FlowGuard Lite does not block traffic automatically. Instead, it generates copyable, target-specific firewall rules templates.

### Supported Platforms

#### MikroTik RouterOS
Generates RouterOS CLI commands to block traffic via address lists:
```routeros
/ip firewall address-list add list=FlowGuardBlock address=192.168.1.50 comment="FlowGuard Block Alert ID: 123"
```

#### Ubiquiti UniFi
Generates JSON API payloads to add the target IP address to a firewall group.

#### OPNsense & pfSense
Generates configuration blocks or aliases that block outbound traffic.
