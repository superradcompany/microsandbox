// ffi-setup installs one explicitly selected native library, never host runtime files.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	msb "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	kind := flag.String("kind", "", "local or remote")
	source := flag.String("source", "", "exact HTTPS release artifact or offline native file")
	digest := flag.String("sha256", "", "SHA256 from trusted release metadata (required)")
	target := flag.String("target", "", "target os-arch; Linux uses linux-{amd64,arm64}-gnu")
	cache := flag.String("cache", "", "native cache directory (default: OS user cache/microsandbox/ffi)")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	path, err := msb.InstallNativeProvider(ctx, msb.NativeInstallOptions{Kind: msb.ContextKind(*kind), Source: *source, SHA256: *digest, Target: *target, CacheDir: *cache})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(path)
}
