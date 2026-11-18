package microsandbox

import (
	"context"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Service is a public URL for one sandbox port.
// Services require a cloud backend; accessors make no request. Later calls on a
// Service use the backend that returned it. A copy of a Service shares its
// native handle.
type Service struct {
	info   ffi.ServiceInfo
	handle *serviceHandle
}

// serviceHandle owns a native Service handle for every copy of a Service.
type serviceHandle struct {
	id atomic.Uint64
}

// closeServiceHandle is replaced in tests to observe releases.
var closeServiceHandle = ffi.CloseService

// ServiceTarget is the sandbox and port that receive a Service's requests.
type ServiceTarget = ffi.ServiceTarget

// ServicePage is one page returned by ListServices or ListServicesWith.
type ServicePage struct {
	Services   []*Service
	NextCursor *string
}

// ServiceListOption configures one paginated ListServicesWith request.
type ServiceListOption func(*ffi.ServiceListOptions)

// CreateService creates a Service for a running target.
// It does not retry; get the Service if ctx ends after the request is sent.
func CreateService(ctx context.Context, slug string, target ServiceTarget) (*Service, error) {
	info, err := ffi.CreateService(ctx, ffi.ServiceCreateRequest{Slug: slug, Target: target})
	if err != nil {
		return nil, wrapServiceChange(err)
	}
	return newService(info), nil
}

// GetService returns a Service by slug.
func GetService(ctx context.Context, slug string) (*Service, error) {
	info, err := ffi.GetService(ctx, slug)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return newService(info), nil
}

// ListServices returns the first page of Services in slug order.
func ListServices(ctx context.Context) (*ServicePage, error) {
	return ListServicesWith(ctx)
}

// ListServicesWith returns a configured page of the organization's Services.
// A limit outside 1 through 100 fails with ErrInvalidConfig.
func ListServicesWith(ctx context.Context, configure ...ServiceListOption) (*ServicePage, error) {
	options := ffi.ServiceListOptions{}
	for _, apply := range configure {
		apply(&options)
	}
	page, err := ffi.ListServices(ctx, options)
	if err != nil {
		return nil, wrapFFI(err)
	}
	services := make([]*Service, len(page.Services))
	for i, info := range page.Services {
		services[i] = newService(info)
	}
	return &ServicePage{Services: services, NextCursor: page.NextCursor}, nil
}

// WithServiceListSandbox only lists Services whose target is the named sandbox.
func WithServiceListSandbox(name string) ServiceListOption {
	return func(options *ffi.ServiceListOptions) { options.Sandbox = &name }
}

// WithServiceListCursor continues after a cursor returned by a previous page.
func WithServiceListCursor(cursor string) ServiceListOption {
	return func(options *ffi.ServiceListOptions) { options.Cursor = &cursor }
}

// WithServiceListLimit sets the maximum number of Services in one page: 1
// through 100, default 20.
func WithServiceListLimit(limit uint32) ServiceListOption {
	return func(options *ffi.ServiceListOptions) { options.Limit = &limit }
}

// Slug returns the Service's slug.
func (s *Service) Slug() string { return s.info.Slug }

// URL returns the Service's public URL as returned by the backend.
func (s *Service) URL() string { return s.info.URL }

// Status reports whether the Service routes requests, is disabled, or has no
// target, as of the read that returned s. Refresh returns a current copy.
func (s *Service) Status() ServiceStatus { return ServiceStatus(s.info.Status) }

// Target returns the target, or nil when the Service is detached.
func (s *Service) Target() *ServiceTarget {
	if s.info.Target == nil {
		return nil
	}
	target := *s.info.Target
	return &target
}

// CreatedAt returns when the organization created the Service.
func (s *Service) CreatedAt() time.Time { return s.info.CreatedAt }

// UpdatedAt returns when the Service's state last changed, including a detach.
func (s *Service) UpdatedAt() time.Time { return s.info.UpdatedAt }

// Update changes the target.
// It does not retry; get and check the Service when the error's Changed field is ChangeUnknown.
func (s *Service) Update(ctx context.Context, target ServiceTarget) (*Service, error) {
	handle, err := s.openHandle(true)
	if err != nil {
		return nil, err
	}
	request := ffi.ServiceUpdateRequest{Target: &target}
	info, err := ffi.UpdateService(ctx, handle, request)
	runtime.KeepAlive(s.handle)
	if err != nil {
		return nil, wrapServiceChange(err)
	}
	return newService(info), nil
}

// Enable enables the Service without retrying.
// To enable a detached Service, set a running target with Update instead.
func (s *Service) Enable(ctx context.Context) (*Service, error) {
	handle, err := s.openHandle(true)
	if err != nil {
		return nil, err
	}
	info, err := ffi.EnableService(ctx, handle)
	runtime.KeepAlive(s.handle)
	if err != nil {
		return nil, wrapServiceChange(err)
	}
	return newService(info), nil
}

// Disable disables the Service without retrying while retaining its target.
func (s *Service) Disable(ctx context.Context) (*Service, error) {
	handle, err := s.openHandle(true)
	if err != nil {
		return nil, err
	}
	info, err := ffi.DisableService(ctx, handle)
	runtime.KeepAlive(s.handle)
	if err != nil {
		return nil, wrapServiceChange(err)
	}
	return newService(info), nil
}

// Remove removes the Service and releases its slug without retrying.
func (s *Service) Remove(ctx context.Context) error {
	handle, err := s.openHandle(true)
	if err != nil {
		return err
	}
	err = ffi.RemoveService(ctx, handle)
	runtime.KeepAlive(s.handle)
	return wrapServiceChange(err)
}

// Refresh gets the Service again and returns its current state. s is not changed.
func (s *Service) Refresh(ctx context.Context) (*Service, error) {
	handle, err := s.openHandle(false)
	if err != nil {
		return nil, err
	}
	info, err := ffi.RefreshService(ctx, handle)
	runtime.KeepAlive(s.handle)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return newService(info), nil
}

// Close releases the native handle shared by s and its copies; later requests
// from any of them return ErrInvalidHandle; accessors still answer. It does not
// remove the Service. Calling Close is optional: the handle is released once no
// copy is reachable. Close is safe to call more than once and from several
// goroutines.
func (s *Service) Close() error {
	if s == nil || s.handle == nil {
		return nil
	}
	return wrapFFI(s.handle.close())
}

func (s *Service) openHandle(change bool) (uint64, error) {
	if s != nil && s.handle != nil {
		if id := s.handle.id.Load(); id != 0 {
			return id, nil
		}
	}
	err := &Error{Kind: ErrInvalidHandle, Message: "service handle closed"}
	if change {
		err.Changed = ChangeUnchanged
	}
	return 0, err
}

func (h *serviceHandle) close() error {
	id := h.id.Swap(0)
	if id == 0 {
		return nil
	}
	runtime.SetFinalizer(h, nil)
	return closeServiceHandle(id)
}

// newService wraps a native Service and releases its handle once the owner is unreachable.
func newService(info *ffi.ServiceInfo) *Service {
	handle := &serviceHandle{}
	handle.id.Store(info.Handle)
	runtime.SetFinalizer(handle, func(handle *serviceHandle) { _ = handle.close() })

	serviceInfo := *info
	serviceInfo.Handle = 0
	return &Service{info: serviceInfo, handle: handle}
}
