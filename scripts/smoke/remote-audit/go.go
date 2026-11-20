// Opt-in remote audit. Run with the rebuilt FFI and only disposable resources.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	msb "github.com/superradcompany/microsandbox/sdk/go"
	"os"
	"strings"
	"time"
)

var rows []map[string]any

func check(name string, fn func(context.Context) error) bool {
	c, cancel := context.WithTimeout(context.Background(), 420*time.Second)
	defer cancel()
	e := fn(c)
	r := map[string]any{"feature": name, "verdict": "PASS"}
	if e == nil && (strings.Contains(name, "missing") || strings.Contains(name, "cleanup_verified")) {
		r["verdict"] = "FAIL"
		r["reason"] = "expected_not_found"
	}
	if e != nil {
		message := strings.ToLower(e.Error())
		reason := "sdk_error"
		switch {
		case strings.Contains(message, "untagged enum createrequest"):
			reason = "config_projection"
		case strings.Contains(message, "unsupported") || strings.Contains(message, "not supported") || strings.Contains(message, "local-only"):
			reason = "unsupported"
		case strings.Contains(message, "not found") || strings.Contains(message, "404"):
			reason = "not_found"
		case strings.Contains(message, "deadline"):
			reason = "timeout"
		}
		r["reason"] = reason
		r["verdict"] = "FAIL"
		if reason == "unsupported" {
			r["verdict"] = "UNSUPPORTED"
		}
		if strings.Contains(name, "missing") || strings.Contains(name, "cleanup_verified") {
			if reason == "not_found" {
				r["verdict"] = "PASS"
			}
		}
	}
	rows = append(rows, r)
	json.NewEncoder(os.Stdout).Encode(r)
	b, _ := json.MarshalIndent(map[string]any{"sdk": "go", "rows": rows}, "", "  ")
	os.WriteFile(os.Getenv("MSB_AUDIT_REPORT"), append(b, '\n'), 0600)
	return e == nil
}
func main() {
	if os.Getenv("MSB_REMOTE_AUDIT") != "1" {
		panic("opt-in required")
	}
	if _, e := msb.LoadNativeProvider(os.Getenv("MSB_SELECTOR_NATIVE_LIBRARY"), msb.ContextRemote); e != nil {
		panic("native provider unavailable")
	}
	bytes := make([]byte, 4)
	rand.Read(bytes)
	name := "audit-go-" + hex.EncodeToString(bytes)
	data, _ := json.Marshal(map[string]string{"prefix": name})
	os.WriteFile(os.Getenv("MSB_AUDIT_REPORT")+".resources.json", data, 0600)
	s, e := msb.SandboxRemote()
	if e != nil {
		panic("remote selector failed")
	}
	v, _ := msb.VolumeRemote()
	p, _ := msb.SnapshotRemote()
	var sb, restored *msb.Sandbox
	var vol *msb.Volume
	var snap *msb.Snapshot
	defer func() {
		if restored != nil {
			check("restore_cleanup", func(c context.Context) error { return restored.Destroy(c) })
		}
		if snap != nil {
			check("snapshot_cleanup", func(c context.Context) error { return snap.Destroy(c, false) })
		}
		if sb != nil {
			check("sandbox_cleanup", func(c context.Context) error { return sb.Destroy(c) })
		}
		if vol != nil {
			check("volume_cleanup", func(c context.Context) error { return vol.Destroy(c) })
		}
		check("sandbox_cleanup_verified", func(c context.Context) error { _, e := s.Get(c, name); return e })
		check("volume_cleanup_verified", func(c context.Context) error { _, e := v.Get(c, name); return e })
		if snap != nil {
			check("snapshot_cleanup_verified", func(c context.Context) error { _, e := p.Get(c, snap.Reference()); return e })
		}
		for _, row := range rows {
			if row["verdict"] == "FAIL" {
				os.Exit(1)
			}
		}
	}()
	check("sandbox_list", func(c context.Context) error { _, e := s.List(c); return e })
	check("volume_list", func(c context.Context) error { _, e := v.List(c); return e })
	check("snapshot_list", func(c context.Context) error { _, e := p.List(c); return e })
	check("sandbox_missing", func(c context.Context) error { _, e := s.Get(c, name+"-missing"); return e })
	check("volume_missing", func(c context.Context) error { _, e := v.Get(c, name+"-missing"); return e })
	check("snapshot_missing", func(c context.Context) error { _, e := p.Get(c, name+"-missing"); return e })
	check("volume_default", func(c context.Context) error { _, e := v.GetDefault(c); return e })
	check("volume_create", func(c context.Context) error { var e error; vol, e = v.Create(c, name); return e })
	if vol != nil {
		check("volume_info", func(c context.Context) error { _, e := vol.Info(c); return e })
		fs := vol.FS()
		check("volume_fs_mkdir", func(c context.Context) error { return fs.Mkdir(c, "audit") })
		check("volume_fs_write", func(c context.Context) error { return fs.Write(c, "audit/a", []byte("hello")) })
		check("volume_fs_read", func(c context.Context) error {
			b, e := fs.Read(c, "audit/a")
			if e == nil && string(b) != "hello" {
				return fmt.Errorf("bytes differ")
			}
			return e
		})
		check("volume_fs_exists", func(c context.Context) error {
			b, e := fs.Exists(c, "audit/a")
			if e == nil && !b {
				return fmt.Errorf("file absent")
			}
			return e
		})
		check("volume_fs_remove", func(c context.Context) error { return fs.RemoveAll(c, "audit") })
	}
	if !check("sandbox_create", func(c context.Context) error {
		var e error
		sb, e = s.Create(c, name, msb.WithImage("python"), msb.WithEphemeral(false), msb.WithEnv(map[string]string{"AUDIT_ENV": "retained"}))
		return e
	}) {
		return
	}
	check("sandbox_identity", func(c context.Context) error {
		other, e := s.Get(c, name)
		if e == nil && other.ID() != sb.ID() {
			return fmt.Errorf("identity differs")
		}
		return e
	})
	check("sandbox_info", func(c context.Context) error { _, e := sb.Info(c); return e })
	check("sandbox_status", func(c context.Context) error { _, e := sb.Status(c); return e })
	check("sandbox_config", func(c context.Context) error { _, e := sb.Config(c); return e })
	check("failure_message", func(c context.Context) error { _, e := sb.LastFailureMessage(c); return e })
	check("get_running", func(c context.Context) error { _, e := s.GetRunning(c, name); return e })
	check("ensure_running", sb.EnsureRunning)
	check("exec_options", func(c context.Context) error {
		o, e := sb.Exec(c, "/bin/sh", []string{"-c", "printf \"$OVERRIDE:$PWD\"; printf err >&2; exit 7"}, msb.WithExecCwd("/tmp"), msb.WithExecEnv(map[string]string{"OVERRIDE": "set"}))
		if e == nil && (o.Stdout() != "set:/tmp" || o.Stderr() != "err" || o.ExitCode() != 7) {
			return fmt.Errorf("output differs")
		}
		return e
	})
	check("shell", func(c context.Context) error {
		o, e := sb.Shell(c, "printf \"$AUDIT_ENV\"")
		if e == nil && o.Stdout() != "retained" {
			return fmt.Errorf("environment differs")
		}
		return e
	})
	check("exec_collect_repeat_wait", func(c context.Context) error {
		h, e := sb.ExecStream(c, "/bin/sh", []string{"-c", "printf stream; exit 3"})
		if e != nil {
			return e
		}
		defer h.Close()
		o, e := h.Collect(c)
		if e != nil {
			return e
		}
		for i := 0; i < 2; i++ {
			code, e := h.Wait(c)
			if e != nil {
				return e
			}
			if code != o.ExitCode() {
				return fmt.Errorf("completion differs")
			}
		}
		return nil
	})
	check("exec_stdin", func(c context.Context) error {
		h, e := sb.ExecStream(c, "cat", nil, msb.WithExecStdinPipe())
		if e != nil {
			return e
		}
		defer h.Close()
		w := h.TakeStdin()
		if w == nil {
			return fmt.Errorf("missing stdin")
		}
		if _, e = w.Write([]byte("input")); e != nil {
			return e
		}
		if e = w.Close(); e != nil {
			return e
		}
		o, e := h.Collect(c)
		if e == nil && o.Stdout() != "input" {
			return fmt.Errorf("stdin differs")
		}
		return e
	})
	check("exec_kill", func(c context.Context) error {
		h, e := sb.ExecStream(c, "sleep", []string{"60"})
		if e != nil {
			return e
		}
		defer h.Close()
		if e = h.Kill(c); e != nil {
			return e
		}
		_, e = h.Wait(c)
		return e
	})
	fs := sb.FS()
	check("fs_mkdir", func(c context.Context) error { return fs.Mkdir(c, "/tmp/audit") })
	check("fs_write", func(c context.Context) error { return fs.Write(c, "/tmp/audit/a", []byte("hello")) })
	check("fs_read", func(c context.Context) error {
		b, e := fs.Read(c, "/tmp/audit/a")
		if e == nil && string(b) != "hello" {
			return fmt.Errorf("bytes differ")
		}
		return e
	})
	check("fs_stat", func(c context.Context) error { _, e := fs.Stat(c, "/tmp/audit/a"); return e })
	check("fs_list", func(c context.Context) error { _, e := fs.List(c, "/tmp/audit"); return e })
	check("fs_copy", func(c context.Context) error { return fs.Copy(c, "/tmp/audit/a", "/tmp/audit/b") })
	check("fs_rename", func(c context.Context) error { return fs.Rename(c, "/tmp/audit/b", "/tmp/audit/c") })
	check("fs_remove", func(c context.Context) error {
		if e := fs.Remove(c, "/tmp/audit/a"); e != nil {
			return e
		}
		if e := fs.Remove(c, "/tmp/audit/c"); e != nil {
			return e
		}
		return fs.RemoveDir(c, "/tmp/audit")
	})
	check("ping", func(c context.Context) error { _, e := sb.Ping(c); return e })
	check("touch", func(c context.Context) error { _, e := sb.Touch(c); return e })
	check("metrics", func(c context.Context) error { _, e := sb.Metrics(c); return e })
	check("logs", func(c context.Context) error { _, e := sb.Logs(c, msb.LogOptions{}); return e })
	check("jobs_list", func(c context.Context) error { _, e := sb.ListJobs(c); return e })
	check("job_create", func(c context.Context) error {
		j, e := sb.ExecDetached(c, "true", nil)
		if e != nil {
			return e
		}
		_, e = j.Wait(c)
		return e
	})
	check("pause", sb.Pause)
	check("resume", sb.Resume)
	check("detach", sb.Detach)
	check("stop", func(c context.Context) error { return sb.Stop(c) })
	check("wait_stopped", func(c context.Context) error { _, e := sb.WaitUntilStopped(c); return e })
	check("snapshot_create", func(c context.Context) error {
		var e error
		snap, e = p.Create(c, msb.SnapshotCreateOptions{Name: name, FromSandbox: name})
		return e
	})
	if snap != nil {
		check("snapshot_get", func(c context.Context) error { _, e := p.Get(c, snap.Reference()); return e })
		check("snapshot_manifest", func(c context.Context) error { _, e := snap.Manifest(c); return e })
		check("snapshot_state", func(c context.Context) error { _, e := snap.State(c); return e })
		check("snapshot_verify", func(c context.Context) error { _, e := snap.Verify(c); return e })
		check("snapshot_restore", func(c context.Context) error {
			var e error
			restored, e = s.Restore(c, snap.Reference(), name+"-restore")
			return e
		})
		if restored != nil {
			check("restored_exec", func(c context.Context) error { _, e := restored.Exec(c, "true", nil); return e })
		}
	}
	check("start", func(c context.Context) error {
		next, e := s.StartDetached(c, name)
		if e == nil {
			sb = next
		}
		return e
	})
	check("restart", func(c context.Context) error {
		next, e := sb.Restart(c)
		if e == nil {
			sb = next
		}
		return e
	})
	check("kill", func(c context.Context) error { return sb.Kill(c) })
	check("stop_again", func(c context.Context) error { return sb.Stop(c) })
	check("automatic_start", func(c context.Context) error { _, e := sb.Exec(c, "true", nil); return e })
}
