# OPNsense & pfSense NetFlow Export Configuration Guide

This guide explains how to configure OPNsense and pfSense firewalls to export flow telemetry to your FlowGuard Lite instance.

---

## OPNsense Configuration

1. **Log in to your OPNsense Web GUI.**
2. Navigate to **Interfaces** -> **Diagnostics** -> **NetFlow** in the sidebar.
3. In the **NetFlow Settings** panel:
   - **Listening Interfaces:** Select the interfaces you wish to monitor (typically `LAN` and `WAN`).
   - **WAN Interfaces:** Select your `WAN` interface (helps differentiate local vs. external traffic).
   - **Capture Targets:** Enter `<FLOWGUARD_LITE_IP>:2055` (where `<FLOWGUARD_LITE_IP>` is the IP of your FlowGuard Lite host).
   - **Version:** Select `NetFlow v9` or `IPFIX`.
4. Click **Save** and **Apply**.

---

## pfSense Configuration

Since pfSense does not include a native NetFlow exporter out of the box, we recommend installing the lightweight `softflowd` package.

1. **Log in to your pfSense Web GUI.**
2. Navigate to **System** -> **Package Manager** -> **Available Packages**.
3. Search for **softflowd** and click **Install**.
4. Once installed, navigate to **Services** -> **softflowd**.
5. Configure the settings:
   - **Interface:** Select the interfaces to capture flows on (e.g. `LAN`).
   - **Host:** Enter your FlowGuard Lite host IP.
   - **Port:** `2055`
   - **NetFlow Version:** `9`
   - **Active Timeout:** `60` seconds
   - **Inactive Timeout:** `15` seconds
6. Click **Save**.

---

## Validation

Navigate to your FlowGuard Lite **Traffic Analysis** dashboard. Your firewall's IP address should appear in the **Flow Exporters** list, indicating telemetry has begun streaming.
