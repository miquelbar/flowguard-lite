package benchmark

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// SendNetFlowV9Packets generates and sends NetFlow v9 packets over UDP.
func SendNetFlowV9Packets(targetAddr string, count int, seed int64) error {
	conn, err := net.Dial("udp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to dial target UDP address: %w", err)
	}
	defer conn.Close()

	rng := rand.New(rand.NewSource(seed))
	localIPBase := net.ParseIP("192.168.1.0").To4()
	extIPBase := net.ParseIP("8.8.8.0").To4()

	for i := 0; i < count; i++ {
		// Generate random IPs and ports
		srcIP := make(net.IP, 4)
		copy(srcIP, localIPBase)
		srcIP[3] = byte(rng.Intn(250) + 2) // 192.168.1.2 - 192.168.1.251

		dstIP := make(net.IP, 4)
		copy(dstIP, extIPBase)
		dstIP[3] = byte(rng.Intn(250) + 1)

		srcPort := uint16(rng.Intn(65535-1024) + 1024)
		dstPort := uint16(rng.Intn(65535-1024) + 1024)
		if rng.Float32() < 0.7 {
			commonPorts := []uint16{80, 443, 53, 22, 123}
			dstPort = commonPorts[rng.Intn(len(commonPorts))]
		}

		proto := uint8(6) // TCP
		if rng.Float32() < 0.3 {
			proto = 17 // UDP
		}

		bytesCount := uint32(rng.Intn(10000) + 64)
		packetsCount := uint32(rng.Intn(10) + 1)

		packetPayload := GenerateNetFlowV9Packet(srcIP, dstIP, srcPort, dstPort, proto, bytesCount, packetsCount)
		
		_, err = conn.Write(packetPayload)
		if err != nil {
			return fmt.Errorf("failed to write UDP NetFlow packet at index %d: %w", i, err)
		}
		
		// Bounded throttle to prevent loopback socket drops in testing (100 microseconds)
		time.Sleep(100 * time.Microsecond)
	}

	return nil
}

// GenerateNetFlowV9Packet constructs a NetFlow v9 UDP packet payload with a template and matching data flowset.
func GenerateNetFlowV9Packet(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8, bytesCount, packetsCount uint32) []byte {
	buf := new(bytes.Buffer)
	
	// 1. Header (20 bytes)
	binary.Write(buf, binary.BigEndian, uint16(9))                  // Version
	binary.Write(buf, binary.BigEndian, uint16(2))                  // Count (1 template + 1 data flowset)
	binary.Write(buf, binary.BigEndian, uint32(1000))               // SysUptime
	binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))  // UnixSecs
	binary.Write(buf, binary.BigEndian, uint32(1))                  // Sequence Number
	binary.Write(buf, binary.BigEndian, uint32(1234))               // Source ID

	// 2. Template FlowSet (FlowSet ID = 0, length = 36 bytes)
	binary.Write(buf, binary.BigEndian, uint16(0))                  // FlowSet ID (0 for Template)
	binary.Write(buf, binary.BigEndian, uint16(36))                 // Length (8 + 7 * 4 = 36 bytes)
	binary.Write(buf, binary.BigEndian, uint16(256))                // Template ID (>= 256)
	binary.Write(buf, binary.BigEndian, uint16(7))                  // Field Count

	// Fields (Type, Length):
	binary.Write(buf, binary.BigEndian, uint16(8))                  // IPV4_SRC_ADDR (Type 8)
	binary.Write(buf, binary.BigEndian, uint16(4))
	binary.Write(buf, binary.BigEndian, uint16(12))                 // IPV4_DST_ADDR (Type 12)
	binary.Write(buf, binary.BigEndian, uint16(4))
	binary.Write(buf, binary.BigEndian, uint16(7))                  // L4_SRC_PORT (Type 7)
	binary.Write(buf, binary.BigEndian, uint16(2))
	binary.Write(buf, binary.BigEndian, uint16(11))                 // L4_DST_PORT (Type 11)
	binary.Write(buf, binary.BigEndian, uint16(2))
	binary.Write(buf, binary.BigEndian, uint16(4))                  // PROTOCOL (Type 4)
	binary.Write(buf, binary.BigEndian, uint16(1))
	binary.Write(buf, binary.BigEndian, uint16(1))                  // IN_BYTES (Type 1)
	binary.Write(buf, binary.BigEndian, uint16(4))
	binary.Write(buf, binary.BigEndian, uint16(2))                  // IN_PKTS (Type 2)
	binary.Write(buf, binary.BigEndian, uint16(4))

	// 3. Data FlowSet (FlowSet ID = Template ID 256, length = 25 bytes)
	binary.Write(buf, binary.BigEndian, uint16(256))                // FlowSet ID (256)
	binary.Write(buf, binary.BigEndian, uint16(25))                 // Length (4 + 21 = 25 bytes)
	
	// Data fields (must align with template):
	buf.Write(srcIP.To4())
	buf.Write(dstIP.To4())
	binary.Write(buf, binary.BigEndian, srcPort)
	binary.Write(buf, binary.BigEndian, dstPort)
	buf.WriteByte(proto)
	binary.Write(buf, binary.BigEndian, bytesCount)
	binary.Write(buf, binary.BigEndian, packetsCount)
	
	return buf.Bytes()
}

// SendUniFiSyslogPackets generates and sends realistic UniFi SIEM syslog UDP packets.
func SendUniFiSyslogPackets(targetAddr string, count int, seed int64) error {
	conn, err := net.Dial("udp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to dial target UDP address: %w", err)
	}
	defer conn.Close()

	rng := rand.New(rand.NewSource(seed))
	
	categories := []struct {
		tag string
		msg string
	}{
		{"unifi-security", "IDS Alert: Trojan detected from 192.168.30.210"},
		{"unifi-security", "Threat Blocked: malicious IP 198.51.100.4"},
		{"unifi-vpn", "VPN user analyst connected from 203.0.113.12"},
		{"unifi-settings", "Admin user administrator changed settings"},
		{"unifi-updates", "Firmware update completed for UCG-Fiber"},
	}

	for i := 0; i < count; i++ {
		choice := categories[rng.Intn(len(categories))]
		
		// Format message with syslog RFC header (RFC5424 style: <PRIVAL>VERSION TIMESTAMP HOST APP-NAME PROCID MSGID MSG)
		syslogMsg := fmt.Sprintf("<14>1 %s 192.168.1.1 %s - - - %s", time.Now().Format(time.RFC3339), choice.tag, choice.msg)
		
		_, err = conn.Write([]byte(syslogMsg))
		if err != nil {
			return fmt.Errorf("failed to write syslog packet at index %d: %w", i, err)
		}
		
		// Bounded throttle (100 microseconds)
		time.Sleep(100 * time.Microsecond)
	}

	return nil
}
