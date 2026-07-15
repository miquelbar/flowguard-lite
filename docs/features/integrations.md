# External Integrations & Webhooks

FlowGuard Lite interfaces with external security tools and chat programs to provide real-time alerting and responses.

---

## 1. Suricata IDS Alert Ingestion

FlowGuard Lite can ingest alerts from a Suricata intrusion detection system:

*   **Log Location:** Configure the integration to point to your Suricata `eve.json` output path.
*   **Mechanism:** Uses a lightweight tailing library to follow the log in real-time.
*   **Correlation:** Matches Suricata threat categories (e.g. *Trojan activity*, *Command and Control*) with NetFlow timestamps to boost device risk scores.

---

## 2. Outbound Alert Webhooks

When an anomaly is detected, FlowGuard Lite dispatches notifications.
Configure Slack/Discord, Generic Webhook, and Telegram independently under Settings. Notification rules then choose one or more channel targets.

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
Dispatches plain-text messages through the Telegram Bot API. FlowGuard intentionally does not set Telegram `parse_mode`; anomaly types, IPs, URLs, and evidence text can contain Markdown or HTML control characters and should never break notification delivery.

```json
{
  "chat_id": "693221",
  "text": "FlowGuard Lite Test Alert\n\nIP Address: 192.168.1.99\nType: test_alert\nSeverity: info\nDescription: This is a FlowGuard Lite synchronous notification test alert."
}
```

To configure Telegram:

1. Create a bot with BotFather and copy the bot token.
2. Open a direct chat with the bot and send `/start`. For group delivery, add the bot to the group first.
3. Send any message to the bot or group.
4. Open `https://api.telegram.org/bot<TOKEN>/getUpdates`.
5. Use `message.chat.id` as `telegram_chat_id`. Do not use `message.from.id` unless it is the same value as `message.chat.id`.
6. Save the token and chat ID under **Settings → Notifications & Routing → Telegram Bot**.
7. Click **Test Telegram Bot Connection** before enabling notification rules that target `telegram`.

Common Telegram diagnostics:

*   `context deadline exceeded`: the container could not complete the outbound HTTPS request. Check DNS/egress firewall. Docker hosts with broken IPv6 egress should use a FlowGuard build that prefers IPv4 for outbound notifications.
*   `can't parse entities`: an older build sent Markdown/HTML parse mode. Upgrade; current builds send plain text.
*   `chat not found`: the token is valid, but the bot cannot see the target chat. Send `/start` in private chat, add the bot to the group/channel, and copy `message.chat.id` from `getUpdates`.

#### Generic JSON Payload
Sends a raw JSON object detailing the event for third-party scripts.

### Custom Webhook Headers

Generic outbound webhook requests can include custom authentication headers configured from the Settings UI, `config.yaml`, or the `FLOWGUARD_WEBHOOK_HEADERS` JSON environment override. Common examples are `Authorization: Bearer ...` or `X-Webhook-Token: ...`.

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
