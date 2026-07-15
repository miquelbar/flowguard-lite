package netclient

import (
	"context"
	"net"
	"net/http"
	"time"
)

const defaultDialTimeout = 5 * time.Second

// NewHTTPClient returns an outbound HTTP client that prefers IPv4 while keeping
// IPv6 fallback. This avoids long stalls on Docker hosts with broken IPv6 egress.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           preferIPv4Dialer(defaultDialTimeout),
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

func preferIPv4Dialer(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	baseDialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return baseDialer.DialContext(ctx, network, address)
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return baseDialer.DialContext(ctx, network, address)
		}

		ordered := preferIPv4(ips)
		var lastErr error
		for _, ip := range ordered {
			dialNetwork := "tcp6"
			if ip.IP.To4() != nil {
				dialNetwork = "tcp4"
			}
			conn, err := baseDialer.DialContext(ctx, dialNetwork, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return baseDialer.DialContext(ctx, network, address)
	}
}

func preferIPv4(ips []net.IPAddr) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			out = append(out, ip)
		}
	}
	for _, ip := range ips {
		if ip.IP.To4() == nil {
			out = append(out, ip)
		}
	}
	return out
}
