package ffi

// StorageUsageReport is the shared Rust storage report. Optional counters preserve JSON null.
type StorageUsageReport struct {
	Images         StorageCategoryUsage `json:"images"`
	Snapshots      StorageCategoryUsage `json:"snapshots"`
	Sandboxes      StorageCategoryUsage `json:"sandboxes"`
	Volumes        StorageCategoryUsage `json:"volumes"`
	BranchMemory   StorageCategoryUsage `json:"branch_memory"`
	SnapshotMemory StorageCategoryUsage `json:"snapshot_memory"`
	Notes          []string             `json:"notes"`
}

// StorageCategoryUsage observes one category; nil counts mean unknown, never zero.
type StorageCategoryUsage struct {
	Count                   *uint64            `json:"count"`
	InUse                   *uint64            `json:"in_use"`
	LogicalBytes            *uint64            `json:"logical_bytes"`
	AllocatedBytes          *uint64            `json:"allocated_bytes"`
	ReclaimableLogicalBytes *uint64            `json:"reclaimable_logical_bytes"`
	Items                   []StorageItemUsage `json:"items"`
	Notes                   []string           `json:"notes"`
}

// StorageItemUsage observes one object or shared-cache component.
type StorageItemUsage struct {
	Name           string   `json:"name"`
	Path           string   `json:"path"`
	LogicalBytes   *uint64  `json:"logical_bytes"`
	AllocatedBytes *uint64  `json:"allocated_bytes"`
	InUse          *bool    `json:"in_use"`
	Reclaimable    *bool    `json:"reclaimable"`
	Reasons        []string `json:"reasons"`
}

// StoragePruneOptions selects unused runtime backing. Zero values apply pruning without an age filter.
type StoragePruneOptions struct {
	DryRun           bool   `json:"dry_run"`
	OlderThanSeconds uint64 `json:"older_than_seconds"`
}

// StoragePruneReport preserves the runtime's per-file outcomes and logical-byte accounting.
type StoragePruneReport struct {
	DryRun                 bool               `json:"dry_run"`
	Entries                []MemoryCacheEntry `json:"entries"`
	FilesRemoved           uint64             `json:"files_removed"`
	LogicalBytesRemoved    uint64             `json:"logical_bytes_removed"`
	PhysicalBytesReclaimed *uint64            `json:"physical_bytes_reclaimed"`
	Truncated              bool               `json:"truncated"`
}

// MemoryCacheEntry contains one published backing's observed bytes and eligibility outcome.
type MemoryCacheEntry struct {
	Path           string  `json:"path"`
	Kind           string  `json:"kind"`
	LogicalBytes   *uint64 `json:"logical_bytes"`
	AllocatedBytes *uint64 `json:"allocated_bytes"`
	State          string  `json:"state"`
	Error          *string `json:"error"`
}
