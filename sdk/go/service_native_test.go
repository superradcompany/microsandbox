//go:build microsandbox_ffi_path && !windows

// Runs in the FFI smoke step against a freshly built native library:
//
//	MICROSANDBOX_FFI_PATH=/path/to/libmicrosandbox_go_ffi.{so,dylib} \
//	    go test -tags "smoke microsandbox_ffi_path" -count=1 -timeout 2m .

package microsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/bundle"
)

func TestServiceNativePassesResultsAndOutcomesThrough(t *testing.T) {
	if os.Getenv(bundle.FFIPathEnv) == "" {
		t.Skipf("%s not set; skipping native Service test", bundle.FFIPathEnv)
	}
	if os.Getenv("MSB_SERVICE_NATIVE_CHILD") != "1" {
		// A fresh process isolates the native SDK's process-wide backend, which is chosen
		// from the environment on first use.
		home := t.TempDir()
		child := exec.Command(os.Args[0], "-test.run=^TestServiceNativePassesResultsAndOutcomesThrough$", "-test.count=1")
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if !strings.HasPrefix(key, "MSB_") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "MSB_HOME="+home, "MSB_CONFIG_PATH="+filepath.Join(home, "config.json"), "MSB_SERVICE_NATIVE_CHILD=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("native service child: %v\n%s", err, output)
		}
		return
	}

	scenario := loadServiceScenario(t)
	var mu sync.Mutex
	var routes, bodies []string
	requestDispatched := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		route := r.Method + " " + r.URL.Path
		var create struct {
			Slug string `json:"slug"`
		}
		if route == "POST /v1/services" && json.Unmarshal(body, &create) == nil && create.Slug == "cancel-after-dispatch" {
			close(requestDispatched)
			<-r.Context().Done()
			return
		}
		mu.Lock()
		routes = append(routes, route)
		bodies = append(bodies, string(body))
		mu.Unlock()
		reply, ok := scenario.Answers[route]
		if !ok {
			reply = scenarioAnswer{Status: http.StatusNotFound}
		}
		w.Header().Set("Content-Type", "application/json")
		for name, value := range reply.Headers {
			w.Header().Set(name, value)
		}
		w.WriteHeader(reply.Status)
		_, _ = w.Write(reply.Body)
	}))
	defer server.Close()
	t.Setenv("MSB_BACKEND", "cloud")
	t.Setenv("MSB_API_URL", server.URL)
	t.Setenv("MSB_API_KEY", "test")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	svc, err := CreateService(ctx, "shop", ServiceTarget{Sandbox: "web-1", Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	if svc.URL() != "https://shop.<domain>" || *svc.Target() != (ServiceTarget{Sandbox: "web-1", Port: 8080}) {
		t.Fatalf("service lost: %+v", svc)
	}
	if svc.Status() != ServiceStatusEnabled {
		t.Fatalf("service status lost: %s", svc.Status())
	}
	if !svc.UpdatedAt().Equal(time.Date(2026, 10, 26, 10, 5, 0, 0, time.UTC)) {
		t.Fatalf("updated_at lost: %v", svc.UpdatedAt())
	}

	var unreachable *ServiceError
	if _, err := svc.Enable(ctx); !errors.As(err, &unreachable) {
		t.Fatalf("unreachable enable: %v", err)
	}
	if unreachable.Slug != "shop" || unreachable.Reason != ServiceReasonTargetUnreachable || unreachable.RetryAfter != 5*time.Second || unreachable.Changed != ChangeUnchanged {
		t.Fatalf("unreachable details lost: %+v", unreachable)
	}
	var unreachableBase *Error
	if !errors.As(unreachable, &unreachableBase) || unreachableBase.Changed != ChangeUnchanged {
		t.Fatalf("unreachable base change state lost: %+v", unreachableBase)
	}

	var lost *ServiceError
	if err := svc.Remove(ctx); !errors.As(err, &lost) {
		t.Fatalf("lost remove: %v", err)
	}
	if lost.Reason != ServiceReasonOutcomeUnknown || lost.Changed != ChangeUnknown {
		t.Fatalf("lost remove details: %+v", lost)
	}

	if _, err := GetService(ctx, "gone"); !IsKind(err, ErrServiceNotFound) {
		t.Fatalf("missing service: %v", err)
	}
	_, err = svc.Update(ctx, ServiceTarget{Sandbox: "web-2", Port: 0})
	if !IsKind(err, ErrInvalidConfig) {
		t.Fatalf("port zero update: %v", err)
	}
	var updateBase *Error
	if !errors.As(err, &updateBase) || updateBase.Changed != ChangeUnchanged {
		t.Fatalf("port zero update change state lost: %+v", updateBase)
	}

	cancelledCtx, cancelRequest := context.WithCancel(context.Background())
	cancelledResult := make(chan error, 1)
	go func() {
		_, err := CreateService(cancelledCtx, "cancel-after-dispatch", ServiceTarget{Sandbox: "web-1", Port: 8080})
		cancelledResult <- err
	}()
	select {
	case <-requestDispatched:
		cancelRequest()
	case <-time.After(5 * time.Second):
		cancelRequest()
		t.Fatal("cancelled Service request was not dispatched")
	}
	select {
	case err := <-cancelledResult:
		var cancelled *Error
		if !errors.As(err, &cancelled) || cancelled.Changed != ChangeUnknown || !errors.Is(err, context.Canceled) {
			t.Fatalf("post-dispatch cancellation = %+v, want cancelled and unknown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled Service request did not return")
	}

	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx); !IsKind(err, ErrInvalidHandle) {
		t.Fatalf("refresh after close = %v, want ErrInvalidHandle", err)
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(routes) != len(scenario.Requests) {
		t.Fatalf("unexpected requests: %v", routes)
	}
	for index, expected := range scenario.Requests {
		if routes[index] != expected.Route {
			t.Fatalf("unexpected requests: %v", routes)
		}
		if expected.Body == nil {
			continue
		}
		var got, want any
		if err := json.Unmarshal([]byte(bodies[index]), &got); err != nil {
			t.Fatalf("%s body %q: %v", expected.Route, bodies[index], err)
		}
		if err := json.Unmarshal(expected.Body, &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s body: %s", expected.Route, bodies[index])
		}
	}
}

func TestServiceNativeRefusesLocalBackend(t *testing.T) {
	if os.Getenv(bundle.FFIPathEnv) == "" {
		t.Skipf("%s not set; skipping native Service test", bundle.FFIPathEnv)
	}
	if os.Getenv("MSB_SERVICE_LOCAL_CHILD") != "1" {
		home := t.TempDir()
		child := exec.Command(os.Args[0], "-test.run=^TestServiceNativeRefusesLocalBackend$", "-test.count=1")
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if !strings.HasPrefix(key, "MSB_") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "MSB_HOME="+home, "MSB_CONFIG_PATH="+filepath.Join(home, "config.json"), "MSB_BACKEND=local", "MSB_SERVICE_LOCAL_CHILD=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("native local Service child: %v\n%s", err, output)
		}
		return
	}

	ctx := context.Background()
	for name, operation := range map[string]func() error{
		"create": func() error {
			_, err := CreateService(ctx, "shop", ServiceTarget{Sandbox: "web", Port: 8080})
			return err
		},
		"get": func() error {
			_, err := GetService(ctx, "shop")
			return err
		},
		"list": func() error {
			_, err := ListServices(ctx)
			return err
		},
	} {
		if err := operation(); !IsKind(err, ErrCloudOnly) {
			t.Fatalf("%s = %v, want ErrCloudOnly", name, err)
		}
	}
}

// serviceScenario is the shared fake-server script in service-binding-scenario.json.
type serviceScenario struct {
	Answers  map[string]scenarioAnswer `json:"answers"`
	Requests []struct {
		Route string          `json:"route"`
		Body  json.RawMessage `json:"body"`
	} `json:"requests"`
}

type scenarioAnswer struct {
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers"`
	Body        json.RawMessage   `json:"body"`
	BodyFixture string            `json:"body_fixture"`
}

// loadServiceScenario reads the scenario and resolves each answer's body fixture.
func loadServiceScenario(t *testing.T) serviceScenario {
	t.Helper()
	const fixtures = "../../packages/microsandbox-types/rust/lib/cloud/fixtures/"
	raw, err := os.ReadFile(fixtures + "service-binding-scenario.json")
	if err != nil {
		t.Fatal(err)
	}
	var scenario serviceScenario
	if err := json.Unmarshal(raw, &scenario); err != nil {
		t.Fatal(err)
	}
	for route, answer := range scenario.Answers {
		if answer.BodyFixture == "" {
			continue
		}
		if answer.Body, err = os.ReadFile(fixtures + answer.BodyFixture); err != nil {
			t.Fatal(err)
		}
		scenario.Answers[route] = answer
	}
	return scenario
}
