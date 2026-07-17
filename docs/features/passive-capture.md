# Passive Network Capture

> [!NOTE]
> Passive Network Capture is an experimental, optional feature with limited validation in real-world environments.

FlowGuard Lite can reduce packets observed on a local interface into the same bounded flow metadata used by its NetFlow and sFlow collectors. Passive capture is optional and disabled when `capture_interface` is empty.


FlowGuard does not persist packet payloads or PCAP files. It requests a 256-byte header snapshot, applies the configured BPF filter in libpcap, aggregates TCP/UDP packets by 5-tuple, and forwards only counters and metadata through the existing detection pipeline.

## Linux Docker deployment

The standard [`deploy/docker-compose.yml`](https://github.com/miquelbar/flowguard-lite/blob/main/deploy/docker-compose.yml) remains unprivileged and does not expose host interfaces. Use the dedicated capture deployment only when passive capture is required:

```bash
export FLOWGUARD_CAPTURE_INTERFACE=eth0
export FLOWGUARD_CAPTURE_BPF_FILTER='ip or ip6'
export FLOWGUARD_CAPTURE_PROMISCUOUS=false

docker compose -f deploy/docker-compose.capture.yml up -d --build
```

The capture Compose file:

- uses `network_mode: host` so a Linux container sees the host network namespace;
- drops all capabilities and adds only `NET_RAW`, which Linux requires for packet sockets;
- enables `no-new-privileges`;
- does not use `privileged: true`;
- omits port mappings because host-network services bind directly to host ports;
- still leaves capture disabled unless `FLOWGUARD_CAPTURE_INTERFACE` is non-empty.

List interface names on the Linux host with:

```bash
ip -brief link
```

The configured interface must exist in the network namespace visible to FlowGuard. A wrong name or invalid BPF filter causes startup to fail explicitly.

### Promiscuous mode

Linux requires `NET_ADMIN` to set promiscuous mode. If `FLOWGUARD_CAPTURE_PROMISCUOUS=true`, add it next to `NET_RAW`:

```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

Do not add `NET_ADMIN` when promiscuous capture is disabled. Do not use `privileged: true`.

## Docker Desktop limitations

Docker Desktop runs Linux containers inside a virtual machine. Even where host networking is available, container-visible interfaces are not equivalent to the macOS or Windows physical interface set. Use passive capture on a native Linux host for router/SPAN/mirror traffic. Bridge-mode capture of a container's own `eth0` is useful for functional testing but does not provide LAN-wide visibility.

## Native deployment

Native builds require libpcap headers and runtime libraries:

```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# Fedora
sudo dnf install libpcap-devel
```

Run FlowGuard with root or an equivalent narrowly scoped packet-capture permission. Prefer service-manager/file capabilities that grant only `CAP_NET_RAW`; add `CAP_NET_ADMIN` only for promiscuous mode. Exact hardening depends on the host distribution and service manager.

## Choosing a BPF filter

The default `ip or ip6` filter admits IPv4 and IPv6 traffic. Narrow it when possible:

```text
tcp or udp
net 192.168.1.0/24
(tcp or udp) and not port 8080
```

Excluding the FlowGuard HTTP and telemetry ports can prevent self-observation or duplicated telemetry. Filter syntax is validated by libpcap when the daemon starts.

## Verification

After restart, confirm the log contains `Passive packet capture started` with the intended interface. Generate TCP or UDP traffic visible on that interface, wait up to 30 seconds for the capture flow flush plus the normal storage flush, and confirm traffic appears in the Overview/Traffic views.

If startup fails:

1. verify the interface name in the same network namespace;
2. verify `NET_RAW` is present;
3. add `NET_ADMIN` only if promiscuous mode is enabled;
4. validate the BPF expression with `tcpdump -d '<filter>'`;
5. check that ports 8080, 2055/UDP, and 6343/UDP are free when using host networking.
