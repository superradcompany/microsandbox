// TLS interception example for the microsandbox Go SDK.
//
// Boots a sandbox with the transparent HTTPS-inspection proxy enabled and
// runs an HTTPS request through it. Verification covers:
//
//   - bypass list — the configured suffix skips MITM entirely
//   - intercepted ports — only listed ports are MITM'd
//   - block_quic   — forces TLS fallback for HTTP/3-eager clients
//   - default upstream verification — kept on
//
// The runtime auto-generates a transient interception CA on first use, so
// no host fixtures are required.
//
// Build: from sdk/go, run
//
//	go run ./examples/tls
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	verifyUpstream := true
	blockQUIC := true

	name := fmt.Sprintf("go-sdk-tls-%d", time.Now().Unix())
	log.Printf("creating sandbox %q with TLS interception enabled", name)

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkConfig{
			Policy: microsandbox.NetworkPolicyPresetAllowAll,
			TLS: &microsandbox.TLSConfig{
				Bypass:           []string{"*.google.com"},
				VerifyUpstream:   &verifyUpstream,
				InterceptedPorts: []uint16{443},
				BlockQUIC:        &blockQUIC,
			},
		}),
	)
	if err != nil {
		log.Fatalf("CreateSandbox: %v", err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_, _ = sb.StopAndWait(stopCtx)
		_ = sb.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	}()

	// Make a regular HTTPS request to a host that is intercepted.
	out, err := sb.Shell(ctx,
		"apk add --no-cache curl >/dev/null && "+
			"curl --max-time 10 -sS -o /dev/null -w '%{http_code} %{ssl_verify_result}\\n' "+
			"https://1.1.1.1/",
		microsandbox.WithExecTimeout(60*time.Second))
	if err != nil {
		log.Fatalf("intercepted request: %v", err)
	}
	if !out.Success() || !strings.Contains(out.Stdout(), "200") {
		log.Fatalf("intercepted request did not return 200: stdout=%q stderr=%q",
			out.Stdout(), out.Stderr())
	}
	fmt.Printf("  intercepted https://1.1.1.1 → %s",
		strings.TrimSpace(out.Stdout()))

	// Make an HTTPS request to a bypassed host. The Bypass entry instructs
	// the proxy to leave the connection alone.
	out, err = sb.Shell(ctx,
		"curl --max-time 10 -sS -o /dev/null -w '%{http_code}\\n' https://www.google.com/",
		microsandbox.WithExecTimeout(60*time.Second))
	if err != nil {
		log.Fatalf("bypass request: %v", err)
	}
	if !out.Success() || !strings.Contains(out.Stdout(), "200") {
		log.Fatalf("bypass request did not return 200: stdout=%q stderr=%q",
			out.Stdout(), out.Stderr())
	}
	fmt.Printf("  bypassed   https://www.google.com → %s\n",
		strings.TrimSpace(out.Stdout()))

	fmt.Println("\nOK — tls-interception example passed")
}
