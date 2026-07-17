# Anomaly Detection & Risk Heuristics

FlowGuard Lite uses statistical modeling rather than opaque machine learning to detect anomalies. This is an experimental framework of heuristics designed for home networks and homelabs.

Detection sensitivity and notification noise are configurable from Settings. Operators can disable specific anomaly types, mute anomaly creation for selected CIDR subnets, keep storing anomalies while suppressing selected notification types, or restrict Slack/Telegram/webhook dispatch to selected VLAN/subnet CIDRs.

---

## 1. Behavioral Baselines

To identify abnormal behaviors, FlowGuard Lite builds device-level behavioral profiles:

*   **Profiling Window:** Traffic is grouped in time windows for each local IP address.
*   **Metrics Tracked:** Packets, bytes, and unique destination ports.
*   **Statistical Calculation:** For each metric, the engine calculates the **Mean** ($\mu$) and **Standard Deviation** ($\sigma$).
*   **Anomaly Threshold:** An alert is generated if the observed value exceeds the baseline by more than a configurable number of standard deviations (usually $\mu + 3\sigma$).

### Explanation Generation
When an anomaly is flagged, the engine logs the exact math behind it:
> *"Device transmitted 52,104 packets in 5 minutes, exceeding the baseline mean of 2,100 packets by 6.2 standard deviations."*

### New destinations and ports

`NEW_DESTINATION` and `NEW_PORT` use retained flow aggregates, not raw packet payloads, to identify external peers and destination ports a device has not used in the past 7 days. To avoid noisy first-run behavior after a clean install or database reset, these detectors only become active after the source device has at least 12 historical aggregate buckets. Until then FlowGuard keeps learning the device instead of alerting on every normal service it discovers.

---

## 2. Fan-out Scan Detection

FlowGuard distinguishes two low-density scanning patterns in each one-minute aggregate window:

*   **Destination fan-out (`DESTINATION_FANOUT`):** one local device contacts at least 32 unique destinations. When a device baseline exists, the effective threshold is raised to the larger of 32 or the learned peer mean plus three standard deviations.
*   **Port fan-out (`PORT_FANOUT`):** one local device contacts at least 16 unique destination ports on the same target.

Both detectors require no more than 12 packets per observed destination or port. This prevents ordinary high-volume sessions from being classified as scans merely because they involve many peers or services. Destination and port sets are capped at 4,096 entries per source/window to keep memory bounded under hostile telemetry.

Each alert states what happened, why it is unusual, the baseline or absolute threshold used, current and expected values, confidence, and the recommended investigation. Alerts of the same type and device are deduplicated for 15 minutes. Existing device, subnet, alert-type, severity, quiet-hour, and cooldown policies continue to apply when the anomaly is stored.

---

## 3. Beaconing Detection

`BEACONING` identifies stable, low-volume periodic communication from a local device to one external destination, port, and protocol tuple.

The detector requires:

*   at least 12 distinct observations;
*   intervals between 90 seconds and 30 minutes;
*   maximum timing deviation within 20% of the mean interval, with a 20-second minimum tolerance for aggregated timestamps;
*   no more than 20 packets or 64 KiB in an observation;
*   an external unicast destination.

Only the 18 most recent timestamps are retained for each tuple. State is capped at 8,192 tuples and entries inactive for two hours are pruned. Internal scheduled services, high-volume sessions, one-minute cloud keepalives, irregular traffic, and series with fewer than 12 observations do not trigger.

The explanation reports the destination tuple, observation count, average period, measured jitter, expected behavior, confidence, and recommended process/DNS/certificate/scheduled-task checks. Existing deduplication and suppression policies apply.

---

## 4. Unexpected Nighttime Traffic

`NIGHTTIME_TRAFFIC` identifies significant activity during 00:00–05:00 in the FlowGuard process timezone after a device has established an active daytime profile.

The detector:

*   learns from 12 distinct significant daytime windows between 07:00 and 23:00;
*   treats traffic as significant at 128 KiB, 100 packets, or 5 unique destinations in one aggregate window;
*   reports the first unexpected nighttime windows;
*   considers nighttime activity expected after 3 distinct significant nighttime windows;
*   retains at most 4,096 device profiles and removes profiles inactive for 14 days.

Small keepalives, devices without enough learned daytime activity, shoulder hours, and devices with an established overnight schedule do not alert. Explanations include the local timestamp/timezone, learned daytime and nighttime counts, traffic counters, confidence, and recommended owner/job/session/destination checks.

Timezone is taken from Go's `time.Local`. Set the host or container `TZ` environment variable to the deployment's actual timezone, for example:

```yaml
environment:
  TZ: Europe/Madrid
```

An incorrect timezone can shift the detection window and create misleading alerts.

---

## 5. Device Profile Change

`DEVICE_PROFILE_CHANGE` detects a persistent change in a device's coarse behavioral role without retaining destination lists or raw flows.

Each one-minute window is reduced to a deterministic signature containing:

*   observed protocols (`tcp`, `udp`, `icmp`, or another IP protocol);
*   service categories such as web, DNS, remote administration, mail, file sharing, database, other system ports, and high ports;
*   a unique-peer band (`0`, `1-4`, `5-15`, or `16+`).

FlowGuard learns 12 windows and requires one signature to appear in at least 9 before establishing the baseline. A different signature must then repeat for 3 consecutive windows before alerting. A return to baseline resets the candidate change, preventing one-off software updates or transient connections from producing an alert. After confirmation, the baseline adapts to the new profile.

State is capped at 4,096 devices, learning tracks at most 8 signatures per device, and profiles inactive for 14 days are removed. Explanations show the old/new signatures, learning and confirmation thresholds, confidence, and recommended role/software/firmware/service/identity checks. Existing deduplication and suppression policies apply.

---

## 6. Known Noisy Device Suppression

An operator can silence an explicitly approved noisy device without disabling a detector globally. Create a policy with:

*   scope `ip`;
*   the device address as `target`;
*   `suppressed: true`.

The rule applies to every anomaly type for that exact IP and stores matching anomalies with status `silenced`, preserving review and audit evidence rather than discarding detections. Other devices remain active. IP scope has higher precedence than subnet, alert-type, and global policies; when multiple IP policies target the same address, the newest policy wins. This allows an operator to re-enable a repaired device with a later non-suppressing IP policy.

IP matching uses parsed address identity, so equivalent IPv6 spellings match the same rule. Use device-wide suppression only for a verified noisy source such as an authorized scanner or infrastructure monitor. Prefer an alert-type policy when only one expected behavior should be silenced.

---

## 7. New Internal Communication

`NEW_INTERNAL_COMMUNICATION` detects a new east-west path between local devices after a source device's internal peer set has been learned.

The detector:

*   evaluates only local-to-local traffic where both source and destination are inside configured local subnets;
*   learns 12 distinct one-minute windows of internal destination peers per source device;
*   requires the same new internal peer to appear in 2 consecutive one-minute windows before alerting;
*   adds the peer to the learned set after alerting to avoid repeated alerts for an approved new relationship;
*   caps state at 4,096 source devices and 256 learned internal peers per source, pruning devices inactive for 14 days.

External destinations, self-traffic, pre-learning traffic, and one-off transient internal contacts do not trigger this alert. Explanations include the new internal peer, learning/confirmation thresholds, current and expected values, confidence, and recommended checks for file sharing, admin access, service discovery, or lateral movement.

---

## 8. Destination Suppression

Anomalies can carry a structured `destination_ip` when the detector knows the relevant destination, such as `NEW_DESTINATION` and `NEW_INTERNAL_COMMUNICATION`.

Policies with scope `ip` or `subnet` match both the source device IP and the structured destination IP. This supports explicitly ignored or approved destinations without parsing free-text descriptions. Matching anomalies are still persisted with status `silenced`; unrelated destinations remain active.

Use destination suppression for known benign services such as backup repositories, monitoring endpoints, or approved internal admin hosts. Prefer exact-IP destination policies before subnet policies to keep the blast radius narrow.

---

## 9. Volumetric DDoS Heuristics (Experimental)

> [!WARNING]
> These flood detection features are experimental statistical heuristics. They are not a replacement for dedicated DDoS mitigation services or firewall traffic shaping.

Volumetric floods (DDoS) are evaluated by checking absolute throughput:

*   **PPS Threshold:** Packets Per Second (PPS) limits.
*   **BPS Threshold:** Bytes Per Second (BPS) limits.
*   **Target IP Monitoring:** Evaluated at the destination IP level.
*   **Deduplication:** A sliding window deduplicates volumetric alerts to prevent alert fatigue.

---

## 10. Experimental Threat Risk Scoring

The Risk Engine assigns each device an index score from `0` to `100` representing an experimental risk level based on heuristic correlation.

### Risk Level Ranges
*   **Low Risk:** `0 - 39`
*   **Medium Risk:** `40 - 74`
*   **High Risk:** `75 - 100`

### Scoring Heuristics
The risk score is calculated by combining:
1.  **Anomaly Events:** Detections flagged by behavioral baselines.
2.  **Suricata IDS Events:** External signature-based rule matches.
3.  **Correlation Booster:** If a device triggers both a baseline anomaly and a Suricata IDS signature match within the same hour, a **Booster Modifier** increases the risk score.

$$\text{Risk Score} = \text{Capping}\left(\sum \text{Base Scores} + \text{Correlation Booster}, 100\right)$$

---

## 11. Heuristic Risk Decay

Threat scores decay over time so that historically flagged devices return to normal if no new suspicious behaviors are observed.

The decay formula applies exponential decay:

$$S(t) = S_0 \times e^{-\lambda t}$$

Where:
*   $S(t)$ is the decayed score at time $t$.
*   $S_0$ is the initial risk score.
*   $\lambda$ is the decay constant.
*   $t$ is the elapsed time since the last suspicious event.
