// Inspect and execute only the exact shared fixture; setup/cleanup is external.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	msb "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	if os.Getenv("MSB_REMOTE_AUDIT") != "1" {
		panic("opt-in required")
	}
	if _, err := msb.LoadNativeProvider(os.Getenv("MSB_SELECTOR_NATIVE_LIBRARY"), msb.ContextRemote); err != nil {
		panic(err)
	}
	data, err := os.ReadFile(os.Getenv("MSB_INSPECTION_FIXTURE"))
	if err != nil {
		panic(err)
	}
	var fixture struct {
		Name string
		ID   string
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	remote, err := msb.RemoteContextFromEnv()
	if err != nil {
		panic(err)
	}
	sb, err := remote.Sandboxes().Get(ctx, fixture.Name)
	if err != nil {
		panic(err)
	}
	defer sb.Close()
	if sb.ID() != fixture.ID {
		panic("identity mismatch")
	}
	var listed *msb.Sandbox
	cursor := ""
	for {
		opts := []msb.SandboxListOption{}
		if cursor != "" {
			opts = append(opts, msb.WithListCursor(cursor))
		}
		page, e := remote.Sandboxes().List(ctx, opts...)
		if e != nil {
			panic(e)
		}
		for _, s := range page.Sandboxes {
			if s.ID() == fixture.ID {
				listed = s
			} else {
				s.Close()
			}
		}
		if listed != nil || page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	if listed == nil {
		panic("fixture missing")
	}
	defer listed.Close()
	rows := []map[string]string{}
	check := func(name string, fn func() error) {
		row := map[string]string{"feature": name, "verdict": "PASS"}
		if e := fn(); e != nil {
			row["verdict"] = "FAIL"
			row["reason"] = strings.ReplaceAll(e.Error(), os.Getenv("MSB_API_KEY"), "[redacted]")
		}
		rows = append(rows, row)
		b, _ := json.MarshalIndent(map[string]any{"sdk": "go", "rows": rows}, "", "  ")
		os.WriteFile(os.Getenv("MSB_AUDIT_REPORT"), append(b, '\n'), 0600)
	}
	output := func(out *msb.ExecOutput, e error, want string) error {
		if e != nil {
			return e
		}
		if strings.TrimSpace(out.Stdout()) != want {
			return fmt.Errorf("unexpected output")
		}
		return nil
	}
	for _, item := range []struct {
		kind string
		s    *msb.Sandbox
	}{{"get", sb}, {"list", listed}} {
		s := item.s
		k := item.kind
		check(k+"_config", func() error {
			c, e := s.Config(ctx)
			if e != nil {
				return e
			}
			if c.Kind != "remote" || c.Spec.Runtime.Shell == nil || *c.Spec.Runtime.Shell != "/bin/bash" || c.Spec.Runtime.Workdir == nil || *c.Spec.Runtime.Workdir != "/tmp" {
				return fmt.Errorf("inspection mismatch")
			}
			return nil
		})
		check(k+"_shell", func() error {
			o, e := s.Shell(ctx, `test -n "$BASH_VERSION" && printf bash`)
			return output(o, e, "bash")
		})
		check(k+"_default_command", func() error { o, e := s.ExecDefault(ctx); return output(o, e, "configured-default") })
		check(k+"_workdir", func() error { o, e := s.Exec(ctx, "pwd", nil); return output(o, e, "/tmp") })
	}
	if os.Getenv("MSB_INSPECTION_DESTROY") == "1" {
		check("destroy", func() error { return sb.Destroy(ctx) })
		check("destroy_absent", func() error {
			found, err := remote.Sandboxes().Get(ctx, fixture.Name)
			if found != nil {
				found.Close()
			}
			if msb.IsKind(err, msb.ErrSandboxNotFound) {
				return nil
			}
			return fmt.Errorf("expected not-found after destroy, got %v", err)
		})
	}
	for _, r := range rows {
		if r["verdict"] == "FAIL" {
			os.Exit(1)
		}
	}
}
