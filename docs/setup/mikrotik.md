# MikroTik RouterOS Traffic Flow Export Configuration Guide

This guide explains how to configure a MikroTik router running RouterOS to export NetFlow/IPFIX telemetry to your FlowGuard Lite instance.

## Option 1: RouterOS CLI Configuration (Recommended)

Connect to your MikroTik router via SSH or WebFig Terminal and execute the following commands:

```routeros
# Enable Traffic Flow collector
/ip traffic-flow set enabled=yes active-flow-timeout=1m inactive-flow-timeout=15s cache-entries=4k

# Add FlowGuard Lite collector destination
/ip traffic-flow target add dst-address=<FLOWGUARD_LITE_IP> port=2055 version=9
```

*Replace `<FLOWGUARD_LITE_IP>` with the actual IP address of your FlowGuard Lite host machine.*

## Option 2: Winbox / WebFig UI Configuration

1. In the left menu, navigate to **IP** -> **Traffic Flow**.
2. Check the **Enabled** box.
3. Configure the timeouts:
   - **Active Flow Timeout:** `00:01:00` (1 minute)
   - **Inactive Flow Timeout:** `00:00:15` (15 seconds)
4. Click **Targets** on the right.
5. Click **Add New** (plus icon) and set:
   - **Src. Address:** `0.0.0.0` (bind all)
   - **Dst. Address:** Enter your FlowGuard Lite host IP.
   - **Port:** `2055`
   - **Version:** `9`
6. Click **OK** and **Apply**.

## Validation

Navigate to your FlowGuard Lite **Traffic Analysis** dashboard. Your MikroTik router IP address should appear under the **Flow Exporters** table, showing incoming packet counts.
