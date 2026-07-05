# UniFi Gateway Flow Export Configuration Guide

This guide explains how to configure a Ubiquiti UniFi Gateway (UDM, UXG, USG) to export NetFlow telemetry to your FlowGuard Lite instance.

## Step-by-Step Configuration

1. **Log in to your UniFi Controller Web UI.**
2. Navigate to **Settings** (gear icon in the bottom left).
3. Go to **System** -> **Advanced**.
4. Scroll down to find the **NetFlow** section.
5. **Enable NetFlow** (toggle switch).
6. Configure the following values:
   - **NetFlow Version:** Select `v9` or `IPFIX` if available (otherwise default v5/v9).
   - **Collector IP:** Enter the IP address of your FlowGuard Lite host machine.
   - **Collector Port:** Set to `2055` (default NetFlow UDP port).
   - **Active Timeout:** Set to `1` minute (ensures real-time anomaly detection works correctly).
   - **Inactive Timeout:** Set to `15` seconds.
7. Click **Apply Changes** at the bottom of the screen.

## Validation

Once provisioned, navigate to your FlowGuard Lite **Traffic Analysis** dashboard. You should see your UniFi Gateway IP address list in the **Flow Exporters** table, with the packet counter incrementing.
