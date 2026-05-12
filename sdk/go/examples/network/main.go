// Network policy example for the microsandbox Go SDK.
//
// Demonstrates each of the four built-in presets and a custom rule list
// with a port range and asymmetric egress / ingress defaults. Each
// configuration boots a sandbox, runs a single representative shell
// command, and prints the result.
//
// Build: from sdk/go, run
//
//	go run ./examples/network
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

type scenario struct {
	name   string
	config *microsandbox.NetworkConfig
	probe  string
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	scenarios := []scenario{
		{
			name:   "public-only (default)",
			config: microsandbox.NetworkPolicy.PublicOnly(),
			probe:  "ping -c 1 -W 5 1.1.1.1 >/dev/null && echo public-OK || echo public-FAIL",
		},
		{
			name:   "none (airgapped)",
			config: microsandbox.NetworkPolicy.None(),
			probe:  "ping -c 1 -W 3 1.1.1.1 >/dev/null && echo public-OK || echo public-FAIL",
		},
		{
			name:   "allow-all",
			config: microsandbox.NetworkPolicy.AllowAll(),
			probe:  "ping -c 1 -W 5 1.1.1.1 >/dev/null && echo public-OK || echo public-FAIL",
		},
		{
			name:   "non-local (public + LAN)",
			config: microsandbox.NetworkPolicy.NonLocal(),
			probe:  "ping -c 1 -W 5 1.1.1.1 >/dev/null && echo public-OK || echo public-FAIL",
		},
		{
			name: "custom: deny-egress except 1.1.1.1:443 (allow public ingress)",
			config: &microsandbox.NetworkConfig{
				DefaultEgress:  microsandbox.PolicyActionDeny,
				DefaultIngress: microsandbox.PolicyActionAllow,
				Rules: []microsandbox.PolicyRule{
					{
						Action:      microsandbox.PolicyActionAllow,
						Direction:   microsandbox.PolicyDirectionEgress,
						Destination: "1.1.1.1/32",
						Protocol:    microsandbox.PolicyProtocolTCP,
						Port:        "443",
					},
				},
			},
			probe: "nc -zv -w 5 1.1.1.1 443 >/dev/null 2>&1 && echo p443-OK || echo p443-FAIL; " +
				"nc -zv -w 5 8.8.8.8 443 >/dev/null 2>&1 && echo other-OK || echo other-FAIL",
		},
		{
			name: "custom: tcp 8000-9000 anywhere",
			config: &microsandbox.NetworkConfig{
				DefaultEgress: microsandbox.PolicyActionDeny,
				Rules: []microsandbox.PolicyRule{
					{
						Action:    microsandbox.PolicyActionAllow,
						Direction: microsandbox.PolicyDirectionEgress,
						Protocols: []microsandbox.PolicyProtocol{microsandbox.PolicyProtocolTCP},
						Ports:     []string{"443-443"},
					},
				},
			},
			probe: "nc -zv -w 5 1.1.1.1 443 >/dev/null 2>&1 && echo in-range-OK || echo in-range-FAIL; " +
				"nc -zv -w 5 1.1.1.1 80 >/dev/null 2>&1 && echo out-range-OK || echo out-range-FAIL",
		},
	}

	for i, s := range scenarios {
		fmt.Printf("\n[%d/%d] %s\n", i+1, len(scenarios), s.name)
		runScenario(ctx, fmt.Sprintf("go-sdk-net-%d-%d", time.Now().Unix(), i), s)
	}

	fmt.Println("\nOK — network example finished")
}

func runScenario(ctx context.Context, name string, s scenario) {
	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(s.config),
		microsandbox.WithReplace(),
	)
	if err != nil {
		log.Fatalf("[%s] CreateSandbox: %v", s.name, err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_, _ = sb.StopAndWait(stopCtx)
		_ = sb.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	}()

	out, err := sb.Shell(ctx, s.probe, microsandbox.WithExecTimeout(20*time.Second))
	if err != nil {
		log.Fatalf("[%s] Shell: %v", s.name, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(out.Stdout()), "\n") {
		if line != "" {
			fmt.Printf("  %s\n", line)
		}
	}
}
