//go:build readiness_native && !windows

package microsandbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

func TestConfiguredContextNative(t *testing.T) {
	library := os.Getenv("MSB_READINESS_NATIVE_LIBRARY")
	if library == "" {
		t.Skip("requires MSB_READINESS_NATIVE_LIBRARY")
	}
	if os.Getenv("MSB_CONFIGURED_CONTEXT_CHILD") != "1" {
		child := exec.Command(os.Args[0], "-test.run=^TestConfiguredContextNative$", "-test.count=1")
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "MSB_") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "MSB_CONFIGURED_CONTEXT_CHILD=1", "MSB_READINESS_NATIVE_LIBRARY="+library)
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, output)
		}
		return
	}
	if err := ffi.Load(library); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(t.TempDir(), "home")
	config := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("MSB_HOME", home)
	t.Setenv("MSB_CONFIG_PATH", config)
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits++
		if req.Header.Get("Authorization") != "Bearer captured-secret" {
			t.Error("credentials were not retained")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()
	writeProfile := func(name string) {
		raw, _ := json.Marshal(map[string]any{"active_profile": name, "profiles": map[string]any{
			"prod":    map[string]any{"kind": "remote", "url": server.URL, "api_key_ref": "env:MSB_TEST_CONTEXT_KEY"},
			"staging": map[string]any{"kind": "remote", "url": "http://127.0.0.1:9", "api_key_ref": "env:MSB_TEST_CONTEXT_KEY"},
		}})
		if err := os.WriteFile(config, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("MSB_TEST_CONTEXT_KEY", "captured-secret")
	writeProfile("prod")
	destination, err := ConfiguredContext()
	if err != nil {
		t.Fatal(err)
	}
	info, err := destination.Info()
	if err != nil || info.Kind != ContextRemote || info.Profile != "prod" || info.Source != "active_profile" || info.APIURL != server.URL {
		t.Fatalf("wrong metadata: %+v %v", info, err)
	}
	encoded, _ := json.Marshal(info)
	if strings.Contains(string(encoded), "captured-secret") {
		t.Fatal("metadata contains credentials")
	}
	if hits != 0 {
		t.Fatal("resolution made a network request")
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatal("resolution created local storage")
	}
	writeProfile("staging")
	t.Setenv("MSB_TEST_CONTEXT_KEY", "changed-secret")
	if _, err := destination.Sandboxes().List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatal("retained operation did not reach original endpoint")
	}
	retained, err := destination.Info()
	if err != nil || retained != info {
		t.Fatal("metadata changed", err)
	}
	next, err := ConfiguredContext()
	if err != nil {
		t.Fatal(err)
	}
	nextInfo, _ := next.Info()
	if nextInfo.Profile != "staging" {
		t.Fatal("new resolution ignored updated configuration")
	}
	t.Setenv("MSB_PROFILE", "prod")
	selected, err := ConfiguredContext()
	if err != nil {
		t.Fatal(err)
	}
	selectedInfo, _ := selected.Info()
	if selectedInfo.Source != "MSB_PROFILE" {
		t.Fatal("profile precedence lost")
	}
	t.Setenv("MSB_BACKEND", "local")
	local, err := ConfiguredContext()
	if err != nil {
		t.Fatal(err)
	}
	localInfo, _ := local.Info()
	if localInfo.Kind != ContextLocal || localInfo.Source != "MSB_BACKEND" || localInfo.APIURL != "" {
		t.Fatal("local override lost")
	}
	t.Setenv("MSB_BACKEND", "")
	t.Setenv("MSB_PROFILE", "missing")
	if _, err := ConfiguredContext(); err == nil {
		t.Fatal("invalid selection did not fail immediately")
	}
}
