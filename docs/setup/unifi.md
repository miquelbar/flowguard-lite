# UniFi Gateway Integration Guide

This guide explains how to connect modern UniFi gateways to FlowGuard Lite without mixing different telemetry protocols.

UniFi Network currently exposes multiple traffic and logging surfaces. They are not interchangeable:

- **Traffic Flows** in `Insights > Flows` are UniFi's internal flow view.
- **NetFlow (IPFIX)** is the external flow export path, when your UniFi version and gateway expose it.
- **Activity Logging (Syslog) > SIEM Server** is an experimental syslog/SIEM event export path, commonly using UDP port `514`.
- **SNMP** is status/counter monitoring. It does not provide flow sessions or SIEM security events.

Reference: Ubiquiti documents Traffic Flows, IPFIX export, and SIEM export separately in its Traffic Flows and Traffic Logging guide:
<https://help.ui.com/hc/en-us/articles/32201256219799-Traffic-Flows-and-Traffic-Logging-in-UniFi-Network>

## What FlowGuard Supports Today

FlowGuard Lite currently supports:

- NetFlow/IPFIX on UDP `2055` (Primary and best-tested flow data source).
- sFlow on UDP `6343` (Experimental collector).
- Optional passive packet capture when FlowGuard can observe the network interface directly (Experimental).
- Optional UniFi Activity Logging/SIEM syslog ingest on the configured UniFi syslog app port, disabled by default. (Experimental support; note that in practice very few useful events are typically received from this source, so it is not a primary visibility option).

UniFi SIEM/syslog events are parsed, counted, and stored as reduced event records bounded by retention. High-confidence security detections and critical events can create FlowGuard anomalies, and device detail views can show related retained UniFi evidence. This integration has limited real-world validation.

Do not configure UniFi `SIEM Server` port `514` to point at FlowGuard's NetFlow/IPFIX port `2055`. They are different protocols.

## Option A: UniFi NetFlow (IPFIX), If Visible

Use this path only if UniFi shows an explicit **NetFlow (IPFIX)** export option.

1. Open UniFi Network.
2. Go to **Settings > CyberSecure > Traffic Logging**.
3. Enable **NetFlow (IPFIX)** if the option is visible.
4. Configure:
   - **Collector IP:** FlowGuard Lite host IP.
   - **Collector Port:** `2055`.
5. Apply changes.
6. In FlowGuard, verify that collector packets and traffic records start increasing.

If this option is not visible, do not assume that `Insights > Flows` means external IPFIX export is available.

## Option B: UniFi Activity Logging / SIEM Server (Experimental)

Some UniFi gateways, including Cloud Gateway Fiber / UCG Fiber deployments, may show:

```txt
Settings > CyberSecure > Traffic Logging > Activity Logging (Syslog) > SIEM Server
```

This screen asks for a server address and usually defaults to port `514`. That is syslog/SIEM event export, not NetFlow/IPFIX. Support for this source is experimental. In practice, very few useful security events are typically generated and exported by the UniFi gateway.

Typical contents can include:

- Admin Activity
- Clients
- Critical
- Devices
- Security Detections
- Triggers
- Updates
- VPN
- Netconsole

FlowGuard uses a dedicated UniFi SIEM/syslog collector for this source, separate from NetFlow/IPFIX. The default FlowGuard app port is `5514/udp` so the daemon does not need privileged port binding. If UniFi requires destination port `514/udp`, map host `514/udp` to the FlowGuard app port, for example with Docker port mapping.

If you need UniFi to retain logs locally, keep UniFi's internal logging retention enabled where the UniFi UI allows it. FlowGuard stores reduced UniFi evidence only; it does not persist raw syslog datagrams indefinitely.

## Option C: Passive Capture Fallback (Experimental)

If UniFi does not expose external IPFIX and FlowGuard needs flow-style analytics, use FlowGuard's passive capture deployment where FlowGuard can observe the traffic path.

Passive capture:

- stores only reduced flow metadata;
- does not store packet payloads;
- does not store PCAP;
- requires the Linux host/network topology to expose the relevant traffic.

See [Passive Network Capture](../features/passive-capture.md).

## Avoid Double Counting

FlowGuard can tag records by collector source, but it cannot automatically know whether two collectors observed the same packet path. Do not enable UniFi IPFIX and passive capture on the same traffic path unless you intentionally want to compare sources. If both observe the same conversations, top talkers and total volume can be double-counted even though Flow Explorer will show the collector source for each aggregate row.

## SNMP Monitoring

SNMP can be useful for interface counters, link status, and device health. It is not a substitute for NetFlow/IPFIX or UniFi SIEM logs:

- It can support interface throughput and error-rate monitoring.
- It can help detect link down/up or counter anomalies.
- It does not provide per-session source/destination/port records.
- It does not provide UniFi Security Detection or Admin Activity event details.

SNMP discovery and metrics support are future optional work with no real-world validation.

## Validation Checklist

- If using IPFIX, FlowGuard's NetFlow/IPFIX packet counters should increase.
- If using SIEM Server, FlowGuard's UniFi syslog collector source should show `listening` and packet/error/drop counters should change.
- Do not expect SIEM Server messages to create FlowGuard traffic records; they are event logs, not IPFIX flow records.
- If using passive capture, verify that FlowGuard sees the expected interface and stores aggregate traffic.
- Keep storage retention bounded.
