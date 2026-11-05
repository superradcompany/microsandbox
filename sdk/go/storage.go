package microsandbox

import (
	"context"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// StorageUsageReport contains backend-scoped storage observations. Logical bytes are file lengths;
// allocated bytes can count shared CoW blocks repeatedly and do not measure exclusive disk usage.
type StorageUsageReport = ffi.StorageUsageReport

// StorageCategoryUsage contains category totals and detailed items. Nil counters mean unknown.
type StorageCategoryUsage = ffi.StorageCategoryUsage

// StorageItemUsage describes one object or shared-cache component, including accounting limits.
type StorageItemUsage = ffi.StorageItemUsage

// StoragePruneOptions controls runtime-memory pruning. DryRun reports candidates without removal;
// OlderThanSeconds excludes files modified more recently than that duration. Zero values apply
// pruning without an age filter. Ownership is always revalidated under the runtime's locks.
type StoragePruneOptions = ffi.StoragePruneOptions

// StoragePruneReport records successful removals and per-file outcomes. LogicalBytesRemoved is
// not physical disk space reclaimed; PhysicalBytesReclaimed remains nil when it cannot be measured.
type StoragePruneReport = ffi.StoragePruneReport

// MemoryCacheEntry describes a published RAM backing. Kind is branch_memory or snapshot_memory;
// State explains eligibility, retention, a changed file, removal, or an observation failure.
type MemoryCacheEntry = ffi.MemoryCacheEntry

// StorageUsage observes this live sandbox's managed directory through its retained backend and
// stable identity. Host bind mounts and shared runtime-memory caches are excluded. Cloud backends
// and older native libraries return ErrUnsupportedOperation. A closed Sandbox returns ErrInvalidHandle.
func (s *Sandbox) StorageUsage(ctx context.Context) (*StorageItemUsage, error) {
	report, err := s.inner.StorageUsage(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return report, nil
}

// StorageUsage observes the selected backend's managed storage. Remote backends and older native
// libraries return ErrUnsupportedOperation; they never silently report local or zero usage.
func StorageUsage(ctx context.Context) (*StorageUsageReport, error) {
	report, err := ffi.StorageUsage(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return report, nil
}

// PruneStorage removes unused runtime RAM from the selected backend without prompting.
// Durable snapshots, named volumes, sandbox disks, and stable handoff locks are excluded.
// Set options.DryRun to preview eligibility. A prior preview does not guarantee later removal.
func PruneStorage(ctx context.Context, options StoragePruneOptions) (*StoragePruneReport, error) {
	report, err := ffi.PruneStorage(ctx, options)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return report, nil
}
