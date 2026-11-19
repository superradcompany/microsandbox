package microsandbox

// Resource selectors capture a destination before any operation. They do not
// change the configured default or the context held by existing resources.

// SandboxLocal captures local configuration, ignoring ambient remote selection.
func SandboxLocal() (*Sandboxes, error) {
	selected, err := NewLocalContext(LocalOptions{})
	if err != nil {
		return nil, err
	}
	return selected.Sandboxes(), nil
}

// SandboxRemote captures MSB_API_KEY and optional MSB_API_URL without network I/O.
func SandboxRemote() (*Sandboxes, error) {
	selected, err := RemoteContextFromEnv()
	if err != nil {
		return nil, err
	}
	return selected.Sandboxes(), nil
}

// VolumeLocal captures local configuration, ignoring ambient remote selection.
func VolumeLocal() (*Volumes, error) {
	selected, err := NewLocalContext(LocalOptions{})
	if err != nil {
		return nil, err
	}
	return selected.Volumes(), nil
}

// VolumeRemote captures MSB_API_KEY and optional MSB_API_URL without network I/O.
func VolumeRemote() (*Volumes, error) {
	selected, err := RemoteContextFromEnv()
	if err != nil {
		return nil, err
	}
	return selected.Volumes(), nil
}

// SnapshotLocal captures local configuration, ignoring ambient remote selection.
func SnapshotLocal() (*Snapshots, error) {
	selected, err := NewLocalContext(LocalOptions{})
	if err != nil {
		return nil, err
	}
	return selected.Snapshots(), nil
}

// SnapshotRemote captures MSB_API_KEY and optional MSB_API_URL without network I/O.
func SnapshotRemote() (*Snapshots, error) {
	selected, err := RemoteContextFromEnv()
	if err != nil {
		return nil, err
	}
	return selected.Snapshots(), nil
}
