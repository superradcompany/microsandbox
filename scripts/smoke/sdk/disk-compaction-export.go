package main

import (
	"context"
	"encoding/json"
	"fmt"
	m "github.com/superradcompany/microsandbox/sdk/go"
	"os"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func measure(label string, fn func() error) {
	start := time.Now()
	must(fn())
	fmt.Printf("%s\tPASS\t%.3fms\n", label, float64(time.Since(start).Microseconds())/1000)
}
func main() {
	ctx := context.Background()
	prefix := os.Getenv("QUAL_SOURCE")
	if prefix == "" {
		prefix = "compact-managed"
	}
	out := os.Getenv("QUAL_ROOT")
	must(os.MkdirAll(out, 0700))
	h, err := m.GetSandbox(ctx, prefix)
	must(err)
	measure("go-plan", func() error {
		r, e := h.Compact(ctx, m.DiskCompactionOptions{DryRun: true})
		if e == nil {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		}
		return e
	})
	measure("go-stopped-compact", func() error { _, e := h.Compact(ctx, m.DiskCompactionOptions{}); return e })
	two := uint32(2)
	measure("go-save-since", func() error {
		return m.Snapshot.Save(ctx, prefix+"-4", out+"/delta.tar.zst", m.SnapshotSaveOptions{Since: prefix + "-2"})
	})
	measure("go-save-last", func() error {
		return m.Snapshot.Save(ctx, prefix+"-4", out+"/last.tar", m.SnapshotSaveOptions{LastLayers: &two, PlainTar: true})
	})
	measure("go-load-base", func() error {
		_, e := m.Snapshot.LoadWithBase(ctx, out+"/delta.tar.zst", out+"/imported", prefix+"-2")
		return e
	})
	for _, disk := range []bool{false, true} {
		func() {
			opts := []m.SandboxOption{m.WithFromSnapshot(out + "/delta.tar.zst"), m.WithSnapshotBase(prefix + "-2")}
			if disk {
				opts = append(opts, m.WithSnapshotDiskOnly())
			}
			var child *m.Sandbox
			measure(fmt.Sprint("go-restore-", disk), func() error {
				var e error
				child, e = m.CreateSandbox(ctx, fmt.Sprint("compact-go-", disk), opts...)
				return e
			})
			defer child.Close()
			defer child.Stop(ctx)
			r, e := child.Shell(ctx, "sha256sum -c /expected && test $(cat /version) = 4")
			must(e)
			if !r.Success() {
				panic(r.Stderr())
			}
			three := uint32(3)
			measure(fmt.Sprint("go-online-compact-", disk), func() error { _, e := child.Compact(ctx, m.DiskCompactionOptions{Layers: &three}); return e })
			r, e = child.Shell(ctx, "sha256sum -c /expected")
			must(e)
			if !r.Success() {
				panic(r.Stderr())
			}
		}()
	}
}
