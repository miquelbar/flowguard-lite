package netclient

import (
	"net"
	"testing"
)

func TestPreferIPv4OrdersIPv4BeforeIPv6(t *testing.T) {
	ordered := preferIPv4([]net.IPAddr{
		{IP: net.ParseIP("2001:db8::1")},
		{IP: net.ParseIP("149.154.166.110")},
		{IP: net.ParseIP("2001:db8::2")},
	})

	if len(ordered) != 3 {
		t.Fatalf("expected 3 addresses, got %d", len(ordered))
	}
	if ordered[0].IP.String() != "149.154.166.110" {
		t.Fatalf("expected IPv4 address first, got %s", ordered[0].IP)
	}
}
