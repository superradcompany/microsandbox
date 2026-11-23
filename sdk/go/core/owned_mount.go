package microsandbox

import "fmt"

// Validate owned selectors before serialization, including when an older native
// library is loaded. A contradictory legacy selector must never take precedence
// after that library ignores the unfamiliar owned field.
func validateOwnedMounts(mounts map[string]MountConfig) error {
	for guest, mount := range mounts {
		if mount.kind != MountKindOwned && mount.Owned == "" {
			continue
		}
		invalid := func(message string) error {
			return &Error{Kind: ErrInvalidConfig, Message: fmt.Sprintf("owned mount %q: %s", guest, message)}
		}
		if mount.kind != MountKindOwned || (mount.Owned != "dir" && mount.Owned != "disk") {
			return invalid("use Mount.Owned with kind dir or disk")
		}
		if mount.Bind != "" || mount.Named != "" || mount.NamedMode != "" || mount.NamedKind != "" ||
			mount.Tmpfs || mount.Disk != "" || mount.Format != "" || mount.Fstype != "" {
			return invalid("cannot specify a source, name, mode, format or filesystem type")
		}
		if mount.Owned == "disk" {
			if mount.SizeMiB == 0 {
				return invalid("disk storage requires positive SizeMiB")
			}
			if mount.QuotaMiB != 0 || mount.StatVirtualization != "" || mount.HostPermissions != "" || mount.Owner != nil {
				return invalid("disk storage does not support quota or metadata policies")
			}
		} else if mount.SizeMiB != 0 {
			return invalid("SizeMiB is only valid for disk storage")
		}
	}
	return nil
}
