# Anomaly Detection & Threat Risk Scoring

FlowGuard Lite uses statistical modeling rather than opaque machine learning to detect anomalies. This ensures that every alert is explainable.

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

---

## 2. Volumetric DDoS Detection

Volumetric floods (DDoS) are evaluated by checking absolute throughput:

*   **PPS Threshold:** Packets Per Second (PPS) limits.
*   **BPS Threshold:** Bytes Per Second (BPS) limits.
*   **Target IP Monitoring:** Evaluated at the destination IP level.
*   **Deduplication:** A sliding window deduplicates volumetric alerts to prevent alert fatigue.

---

## 3. Threat Risk Scoring

The Risk Engine assigns each device an index score from `0` to `100` representing its compromise risk level.

### Risk Level Ranges
*   **Low Risk:** `0 - 39`
*   **Medium Risk:** `40 - 74`
*   **High Risk:** `75 - 100`

### Scoring Formula
The risk score is calculated by combining:
1.  **Anomaly Events:** Detections flagged by behavioral baselines.
2.  **Suricata IDS Events:** External signature-based rule matches.
3.  **Correlation Booster:** If a device triggers both a baseline anomaly and a Suricata IDS signature match within the same hour, a **Booster Modifier** increases the risk score.

$$\text{Risk Score} = \text{Capping}\left(\sum \text{Base Scores} + \text{Correlation Booster}, 100\right)$$

---

## 4. Exponential Risk Decay

Threat scores decay over time so that historically compromised devices return to normal if no new suspicious behaviors are observed.

The decay formula applies exponential decay:

$$S(t) = S_0 \times e^{-\lambda t}$$

Where:
*   $S(t)$ is the decayed score at time $t$.
*   $S_0$ is the initial risk score.
*   $\lambda$ is the decay constant.
*   $t$ is the elapsed time since the last suspicious event.
