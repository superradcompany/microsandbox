//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// TestNetworkPolicyNonLocal verifies the new NonLocal preset accepts
// public + private/LAN egress and blocks loopback/link-local/metadata.
// We can only assert on a public reach here (LAN is environment-specific).
func TestNetworkPolicyNonLocal(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-nonlocal-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(microsandbox.NetworkPolicy.NonLocal()),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	// TCP reach check (wget) rather than ICMP (ping) — many CI runners
	// strip CAP_NET_RAW or block ICMP egress, which would falsely fail
	// what is fundamentally an egress-policy test.
	out, err := sb.Shell(ctx, "wget -q -O - --timeout=10 http://1.1.1.1/",
		microsandbox.WithExecTimeout(20*time.Second))
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !out.Success() {
		t.Errorf("expected NonLocal preset to permit public TCP; stdout=%q stderr=%q",
			out.Stdout(), out.Stderr())
	}
}

// TestCustomPolicyDefaultEgressDeny verifies that DefaultEgress=Deny with no
// matching rule blocks outbound traffic.
func TestCustomPolicyDefaultEgressDeny(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-defegress-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkConfig{
			DefaultEgress:  microsandbox.PolicyActionDeny,
			DefaultIngress: microsandbox.PolicyActionAllow,
			// No matching egress rule: outbound to 1.1.1.1 should be blocked.
			Rules: []microsandbox.PolicyRule{
				{
					Action:      microsandbox.PolicyActionAllow,
					Direction:   microsandbox.PolicyDirectionEgress,
					Destination: "127.0.0.1/32",
				},
			},
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "ping -c 1 -W 3 1.1.1.1",
		microsandbox.WithExecTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if out.Success() {
		t.Errorf("expected default-deny egress to block 1.1.1.1; stdout=%q stderr=%q",
			out.Stdout(), out.Stderr())
	}
}

// TestCustomPolicyAllowSpecificEgress verifies that an explicit allow rule
// for a destination + port combination opens just that path while leaving
// other destinations blocked.
func TestCustomPolicyAllowSpecificEgress(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-allowspec-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkConfig{
			DefaultEgress: microsandbox.PolicyActionDeny,
			Rules: []microsandbox.PolicyRule{
				{
					Action:      microsandbox.PolicyActionAllow,
					Direction:   microsandbox.PolicyDirectionEgress,
					Destination: "1.1.1.1/32",
					Protocol:    microsandbox.PolicyProtocolTCP,
					Port:        "443",
				},
			},
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	// 1.1.1.1:443 should be reachable; 8.8.8.8:443 should not.
	out, err := sb.Shell(ctx,
		"nc -zv -w 5 1.1.1.1 443 2>&1 || echo cloudflare-failed; "+
			"nc -zv -w 5 8.8.8.8 443 2>&1 || echo google-failed",
		microsandbox.WithExecTimeout(20*time.Second))
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	combined := out.Stdout() + out.Stderr()
	if strings.Contains(combined, "cloudflare-failed") {
		t.Errorf("expected 1.1.1.1:443 to be allowed; got %q", combined)
	}
	if !strings.Contains(combined, "google-failed") {
		t.Errorf("expected 8.8.8.8:443 to be blocked; got %q", combined)
	}
}

// TestCustomPolicyPortRange verifies that a port-range rule serialises as
// "8000-9000" and the runtime evaluates it correctly. We test by allowing
// only a narrow range and confirming that an in-range port survives while
// an out-of-range port is blocked.
func TestCustomPolicyPortRange(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-portrange-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkConfig{
			DefaultEgress: microsandbox.PolicyActionDeny,
			Rules: []microsandbox.PolicyRule{
				{
					Action:    microsandbox.PolicyActionAllow,
					Direction: microsandbox.PolicyDirectionEgress,
					// Match any destination on TCP within the port range.
					Destination: "*",
					Protocols:   []microsandbox.PolicyProtocol{microsandbox.PolicyProtocolTCP},
					Ports:       []string{"443-443"},
				},
			},
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	// 443 inside the range — should succeed; 80 outside — should be blocked.
	out, err := sb.Shell(ctx,
		"nc -zv -w 5 1.1.1.1 443 2>&1 || echo p443-failed; "+
			"nc -zv -w 5 1.1.1.1 80 2>&1 || echo p80-failed",
		microsandbox.WithExecTimeout(20*time.Second))
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	combined := out.Stdout() + out.Stderr()
	if strings.Contains(combined, "p443-failed") {
		t.Errorf("expected 443 in range to be allowed; got %q", combined)
	}
	if !strings.Contains(combined, "p80-failed") {
		t.Errorf("expected 80 out of range to be blocked; got %q", combined)
	}
}

// TestCustomPolicyMultiProtocol exercises the Vec<Protocol> wire shape via
// the Protocols slice. Smoke-only: we just confirm creation accepts the
// config and the resulting sandbox is reachable.
func TestCustomPolicyMultiProtocolCreates(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-multiproto-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkConfig{
			DefaultEgress: microsandbox.PolicyActionAllow,
			Rules: []microsandbox.PolicyRule{
				{
					Action:      microsandbox.PolicyActionDeny,
					Direction:   microsandbox.PolicyDirectionEgress,
					Destination: "192.0.2.0/24",
					Protocols: []microsandbox.PolicyProtocol{
						microsandbox.PolicyProtocolTCP,
						microsandbox.PolicyProtocolUDP,
					},
				},
			},
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox with multi-protocol rule: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})
}

// TestCustomPolicyDirectionAny verifies the Direction.Any value (rule
// applies to both egress and ingress) round-trips through the wire format.
func TestCustomPolicyDirectionAnyCreates(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-dirany-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkConfig{
			DefaultEgress:  microsandbox.PolicyActionDeny,
			DefaultIngress: microsandbox.PolicyActionDeny,
			Rules: []microsandbox.PolicyRule{
				{
					Action:      microsandbox.PolicyActionAllow,
					Direction:   microsandbox.PolicyDirectionAny,
					Destination: "127.0.0.1/32",
				},
			},
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})
}

// TestDNSConfigCreates verifies that the DNS sub-config (rebind protection,
// nameservers, query timeout) is accepted by the FFI without error. We
// don't validate runtime DNS behaviour because that depends on the test
// environment's network.
func TestDNSConfigCreates(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-dnscfg-" + t.Name()

	rebind := true
	timeoutMs := uint64(5000)
	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkConfig{
			Policy: microsandbox.NetworkPolicyPresetAllowAll,
			DNS: &microsandbox.DNSConfig{
				RebindProtection: &rebind,
				Nameservers:      []string{"1.1.1.1:53"},
				QueryTimeoutMs:   &timeoutMs,
			},
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "true")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !out.Success() {
		t.Errorf("expected sandbox with DNS config to boot and run a noop")
	}
}

// TestNetworkOnSecretViolationCreates verifies that the network-wide
// on_secret_violation field is accepted. Triggering an actual violation
// requires a TLS-intercepting outbound, which is brittle in CI.
func TestNetworkOnSecretViolationCreates(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-onviolation-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkConfig{
			Policy:            microsandbox.NetworkPolicyPresetPublicOnly,
			OnSecretViolation: microsandbox.ViolationActionBlockAndLog,
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})
}

// TestSecretWithOnViolation exercises the per-secret OnViolation field.
// Per the runtime, the value is applied network-wide (last-write-wins);
// here we only verify the FFI accepts the field.
func TestSecretWithOnViolation(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-secretviol-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithSecrets(microsandbox.Secret.Env(
			"VIOLATION_KEY",
			"value-not-leaked-xyz",
			microsandbox.SecretEnvOptions{
				AllowHosts:  []string{"api.example.com"},
				OnViolation: microsandbox.ViolationActionBlock,
			},
		)),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "printenv VIOLATION_KEY; true")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if strings.Contains(out.Stdout(), "value-not-leaked-xyz") {
		t.Error("secret value leaked into env")
	}
}

// TestTLSConfigUpstreamCACertsCreates ensures the TLSConfig.UpstreamCACerts
// field accepts a list of paths and the create call doesn't error.
// The paths can be empty/absent here — we're testing wiring, not TLS.
func TestTLSConfigUpstreamCACertsCreates(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-upstreamcas-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkConfig{
			Policy: microsandbox.NetworkPolicyPresetAllowAll,
			TLS: &microsandbox.TLSConfig{
				// Don't set actual paths — the runtime accepts an empty slice.
				UpstreamCACerts: []string{},
			},
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})
}

// TestNetworkMaxConnectionsCreates exercises the connection-cap option.
func TestNetworkMaxConnectionsCreates(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-maxconn-" + t.Name()

	max := uint(64)
	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkConfig{
			Policy:         microsandbox.NetworkPolicyPresetAllowAll,
			MaxConnections: &max,
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})
}
