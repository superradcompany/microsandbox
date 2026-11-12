package microsandbox

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

func TestServiceAccessorsAndPage(t *testing.T) {
	created := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	updated := created.Add(5 * time.Minute)
	target := ffi.ServiceTarget{Sandbox: "web", Port: 8080}
	service := &Service{info: ffi.ServiceInfo{
		Slug: "shop", URL: "https://shop.example", Status: "enabled", Target: &target,
		CreatedAt: created, UpdatedAt: updated,
	}}

	if service.Slug() != "shop" || service.URL() != "https://shop.example" {
		t.Fatalf("identity accessors lost data: %+v", service)
	}
	if service.Status() != ServiceStatusEnabled || *service.Target() != (ServiceTarget(target)) {
		t.Fatalf("state accessors lost data: %+v", service)
	}
	if !service.CreatedAt().Equal(created) || !service.UpdatedAt().Equal(updated) {
		t.Fatal("timestamp accessors lost data")
	}
	cursor := "next"
	page := ServicePage{Services: []*Service{service}, NextCursor: &cursor}
	if len(page.Services) != 1 || *page.NextCursor != "next" {
		t.Fatalf("page lost data: %+v", page)
	}

	detached := &Service{info: ffi.ServiceInfo{Status: "detached"}}
	if detached.Status() != ServiceStatusDetached || detached.Target() != nil {
		t.Fatalf("detached state lost: %+v", detached)
	}
}

func TestServiceCopyKeepsHandleAlive(t *testing.T) {
	releases := recordServiceReleases(t)
	var copied *Service
	func() {
		service := newService(&ffi.ServiceInfo{Handle: 41})
		copyValue := *service
		copied = &copyValue
		service = nil

		for range 5 {
			runtime.GC()
		}
		runtime.KeepAlive(copied)
		select {
		case id := <-releases:
			t.Fatalf("released live copied handle %d", id)
		default:
		}
	}()

	copied = nil
	if id := waitForServiceRelease(t, releases); id != 41 {
		t.Fatalf("released handle %d, want 41", id)
	}
}

func TestServiceCloseIsIdempotent(t *testing.T) {
	releases := recordServiceReleases(t)
	service := newService(&ffi.ServiceInfo{Handle: 42})

	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if id := <-releases; id != 42 {
		t.Fatalf("released handle %d, want 42", id)
	}
	select {
	case id := <-releases:
		t.Fatalf("released handle twice: %d", id)
	default:
	}
}

func TestServiceUseAfterClose(t *testing.T) {
	releases := recordServiceReleases(t)
	service := newService(&ffi.ServiceInfo{Handle: 43})
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	<-releases

	ctx := context.Background()
	changes := map[string]func() error{
		"update": func() error {
			_, err := service.Update(ctx, ServiceTarget{Sandbox: "web", Port: 8080})
			return err
		},
		"enable": func() error {
			_, err := service.Enable(ctx)
			return err
		},
		"disable": func() error {
			_, err := service.Disable(ctx)
			return err
		},
		"remove": func() error { return service.Remove(ctx) },
	}
	for name, operation := range changes {
		err := operation()
		var base *Error
		if !IsKind(err, ErrInvalidHandle) || !errors.As(err, &base) || base.Changed != ChangeUnchanged {
			t.Fatalf("%s = %+v, want closed unchanged error", name, err)
		}
	}
	if _, err := service.Refresh(ctx); !IsKind(err, ErrInvalidHandle) {
		t.Fatalf("refresh = %v, want ErrInvalidHandle", err)
	} else {
		var base *Error
		if !errors.As(err, &base) || base.Changed != "" {
			t.Fatalf("refresh change state = %+v, want empty", base)
		}
	}
}

func TestServiceConcurrentClose(t *testing.T) {
	var calls atomic.Int64
	previous := closeServiceHandle
	closeServiceHandle = func(uint64) error {
		calls.Add(1)
		return nil
	}
	t.Cleanup(func() { closeServiceHandle = previous })
	service := newService(&ffi.ServiceInfo{Handle: 44})

	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := service.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	group.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("release calls = %d, want 1", got)
	}
}

func TestServiceCloseWrapsNativeError(t *testing.T) {
	previous := closeServiceHandle
	closeServiceHandle = func(uint64) error {
		return &ffi.Error{Kind: ffi.KindInvalidHandle, Message: "unknown handle"}
	}
	t.Cleanup(func() { closeServiceHandle = previous })
	service := newService(&ffi.ServiceInfo{Handle: 46})

	err := service.Close()
	var base *Error
	if !IsKind(err, ErrInvalidHandle) || !errors.As(err, &base) {
		t.Fatalf("Close = %#v, want wrapped ErrInvalidHandle", err)
	}
}

func TestServiceFinalizerReleasesHandle(t *testing.T) {
	releases := recordServiceReleases(t)
	service := newService(&ffi.ServiceInfo{Handle: 45})
	service = nil
	if id := waitForServiceRelease(t, releases); id != 45 {
		t.Fatalf("released handle %d, want 45", id)
	}
	runtime.KeepAlive(service)
}

func recordServiceReleases(t *testing.T) <-chan uint64 {
	t.Helper()
	releases := make(chan uint64, 64)
	previous := closeServiceHandle
	closeServiceHandle = func(id uint64) error {
		releases <- id
		return nil
	}
	t.Cleanup(func() { closeServiceHandle = previous })
	return releases
}

func waitForServiceRelease(t *testing.T, releases <-chan uint64) uint64 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		select {
		case id := <-releases:
			return id
		default:
			runtime.Gosched()
		}
	}
	t.Fatal("timed out waiting for Service handle release")
	return 0
}

func TestServiceListOptions(t *testing.T) {
	options := ffi.ServiceListOptions{}
	for _, apply := range []ServiceListOption{
		WithServiceListSandbox("web"),
		WithServiceListCursor("next"),
		WithServiceListLimit(25),
	} {
		apply(&options)
	}
	if *options.Sandbox != "web" || *options.Cursor != "next" || *options.Limit != 25 {
		t.Fatalf("options mapped incorrectly: %+v", options)
	}
}
