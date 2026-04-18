// Secrets example for the microsandbox Go SDK.
//
// Exercises: WithSecrets — verifies the real secret value never appears inside
// the guest, and that the placeholder is visible instead.
//
// Build: from sdk/go, run
//
//	cargo build -p microsandbox-go-ffi
//	CGO_LDFLAGS="-L$(git rev-parse --show-toplevel)/target/debug" \
//	  go run ./examples/secrets
//
// Requires a running microsandbox daemon.
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

const (
	secretValue   = "super-secret-value-abcxyz"
	placeholder   = "$MY_API_KEY_PLACEHOLDER"
	allowedHost   = "api.example.com"
	envVarInGuest = "MY_API_KEY"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	name := fmt.Sprintf("go-sdk-secrets-%d", time.Now().Unix())
	log.Printf("creating sandbox %q with one secret", name)

	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithSecrets(microsandbox.SecretOptions{
			EnvVar:      envVarInGuest,
			Value:       secretValue,
			AllowHosts:  []string{allowedHost},
			Placeholder: placeholder,
		}),
	)
	if err != nil {
		log.Fatalf("NewSandbox: %v", err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_, _ = sb.StopAndWait(stopCtx)
		_ = sb.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	}()

	// 1. printenv: the env var in the guest must hold the placeholder, never
	// the real value.
	out, err := sb.Shell(ctx, "printenv "+envVarInGuest+"; true")
	if err != nil {
		log.Fatalf("Shell printenv: %v", err)
	}
	if strings.Contains(out.Stdout(), secretValue) {
		log.Fatalf("FAIL: secret value leaked into sandbox env:\n%s", out.Stdout())
	}
	if !strings.Contains(out.Stdout(), placeholder) {
		log.Fatalf("FAIL: placeholder not visible inside guest env: %q", out.Stdout())
	}
	fmt.Printf("  guest sees placeholder only: %q\n", strings.TrimSpace(out.Stdout()))

	// 2. Full env dump: ensure the secret value appears nowhere.
	out, err = sb.Shell(ctx, "env")
	if err != nil {
		log.Fatalf("Shell env: %v", err)
	}
	if strings.Contains(out.Stdout(), secretValue) {
		log.Fatalf("FAIL: secret value found in full env dump")
	}
	fmt.Printf("  full env dump contains no secret value (%d bytes scanned)\n", len(out.Stdout()))

	fmt.Println("OK — secrets example passed")
}
