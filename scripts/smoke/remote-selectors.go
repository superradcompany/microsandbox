// Opt-in live selector reads. Run from sdk/go; never print credentials or metadata.
package main

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"time"

	msb "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	if os.Getenv("MSB_REMOTE_SELECTOR_LIVE") != "1" {
		panic("Set MSB_REMOTE_SELECTOR_LIVE=1 to opt in")
	}
	if _, err := msb.LoadNativeProvider(os.Getenv("MSB_SELECTOR_NATIVE_LIBRARY"), msb.ContextRemote); err != nil {
		panic("failed to load test native provider")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	results := []map[string]any{}
	status := regexp.MustCompile(`\b(4\d\d|5\d\d)\b`)
	checks := []struct {
		name string
		run  func() error
	}{
		{"sandbox_list", func() error {
			c, e := msb.SandboxRemote()
			if e != nil {
				return e
			}
			_, e = c.List(ctx)
			return e
		}},
		{"volume_list", func() error {
			c, e := msb.VolumeRemote()
			if e != nil {
				return e
			}
			_, e = c.List(ctx)
			return e
		}},
		{"snapshot_list", func() error {
			c, e := msb.SnapshotRemote()
			if e != nil {
				return e
			}
			_, e = c.List(ctx)
			return e
		}},
	}
	failed := false
	for _, check := range checks {
		row := map[string]any{"feature": check.name, "verdict": "PASS"}
		if err := check.run(); err != nil {
			failed = true
			row["verdict"] = "FAIL"
			row["status"] = status.FindString(err.Error())
		}
		results = append(results, row)
		_ = json.NewEncoder(os.Stdout).Encode(row)
	}
	if path := os.Getenv("MSB_SELECTOR_REPORT"); path != "" {
		data, _ := json.MarshalIndent(results, "", "  ")
		_ = os.WriteFile(path, append(data, '\n'), 0600)
	}
	if failed {
		os.Exit(1)
	}
}
