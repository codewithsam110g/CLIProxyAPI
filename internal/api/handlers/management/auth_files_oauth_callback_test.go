package management

import (
	"net"
	"net/http"
	"testing"
)

func TestOAuthCallbackForwarderIsLoopbackOnly(t *testing.T) {
	forwarder, err := startCallbackForwarder(0, "test", "http://127.0.0.1:8317/codex/callback")
	if err != nil {
		t.Fatal(err)
	}
	defer stopCallbackForwarderInstance(0, forwarder)
	host, port, err := net.SplitHostPort(forwarder.server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("callback advertised non-loopback listener %s", forwarder.server.Addr)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get("http://" + forwarder.server.Addr + "/auth/callback?code=synthetic&state=test-state")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "http://127.0.0.1:8317/codex/callback?code=synthetic&state=test-state" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("callback forwarding contract changed: status=%d headers=%v", response.StatusCode, response.Header)
	}
	// An all-interface listener would reserve this port on every IPv4 address.
	// Prove the LAN address remains independently bindable while the callback runs.
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok || network.IP.IsLoopback() || network.IP.To4() == nil {
			continue
		}
		listener, err := net.Listen("tcp4", net.JoinHostPort(network.IP.String(), port))
		if err != nil {
			t.Fatalf("callback occupied a non-loopback interface: %v", err)
		}
		_ = listener.Close()
		return
	}
	t.Log("No non-loopback IPv4 interface available; verified redirect and loopback address")
}
