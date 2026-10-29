package microsandbox

import "testing"

func TestOwnedMountWireShape(t *testing.T) {
	options := marshalCreateOptions(t, WithMounts(map[string]MountConfig{
		"/cache": Mount.Owned(OwnedVolumeOptions{QuotaMiB: 512, Owner: &MountOwner{UID: 0, GID: 0}}),
		"/data":  Mount.Owned(OwnedVolumeOptions{Kind: VolumeKindDisk, SizeMiB: 10240, Noexec: true}),
	}))
	mounts := mustField(t, options, "volumes").(map[string]any)
	for _, guest := range []string{"/cache", "/data"} {
		mount := mounts[guest].(map[string]any)
		for _, legacy := range []string{"bind", "named", "tmpfs", "disk"} {
			if _, ok := mount[legacy]; ok {
				t.Fatalf("owned mount emitted legacy selector %q: %#v", legacy, mount)
			}
		}
	}
	cache := mounts["/cache"].(map[string]any)
	if cache["owned"] != "dir" || cache["quota_mib"] != float64(512) || cache["override_uid"] != float64(0) {
		t.Fatalf("directory wire shape = %#v", cache)
	}
	disk := mounts["/data"].(map[string]any)
	if disk["owned"] != "disk" || disk["size_mib"] != float64(10240) || disk["noexec"] != true {
		t.Fatalf("disk wire shape = %#v", disk)
	}
}

func TestOwnedMountValidationRejectsAmbiguousNativeRequests(t *testing.T) {
	mixed := Mount.Owned(OwnedVolumeOptions{})
	mixed.Named = "shared"
	for name, mount := range map[string]MountConfig{
		"mixed source":       mixed,
		"missing capacity":   Mount.Owned(OwnedVolumeOptions{Kind: VolumeKindDisk}),
		"directory capacity": Mount.Owned(OwnedVolumeOptions{SizeMiB: 64}),
		"disk quota":         Mount.Owned(OwnedVolumeOptions{Kind: VolumeKindDisk, SizeMiB: 64, QuotaMiB: 1}),
		"disk owner":         Mount.Owned(OwnedVolumeOptions{Kind: VolumeKindDisk, SizeMiB: 64, Owner: &MountOwner{}}),
		"invalid kind":       Mount.Owned(OwnedVolumeOptions{Kind: "other"}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateOwnedMounts(map[string]MountConfig{"/data": mount}); err == nil {
				t.Fatal("expected invalid owned mount to fail before entering the native library")
			}
		})
	}
	if err := validateOwnedMounts(map[string]MountConfig{
		"/data":  Mount.Owned(OwnedVolumeOptions{Kind: VolumeKindDisk, SizeMiB: 64}),
		"/cache": Mount.Owned(OwnedVolumeOptions{}),
	}); err != nil {
		t.Fatalf("valid owned mounts rejected: %v", err)
	}
}

func TestOwnedDiskBaseWireShapeAndValidation(t *testing.T) {
	options := marshalCreateOptions(t, WithMounts(map[string]MountConfig{
		"/data": Mount.Owned(OwnedVolumeOptions{Kind: VolumeKindDisk, BasePath: "/srv/bases/app.raw"}),
	}))
	disk := mustField(t, options, "volumes").(map[string]any)["/data"].(map[string]any)
	if disk["owned"] != "disk" || disk["owned_base"] != "/srv/bases/app.raw" {
		t.Fatalf("disk over base wire shape = %#v", disk)
	}
	if _, ok := disk["size_mib"]; ok {
		t.Fatalf("a disk over a base takes its size from the base: %#v", disk)
	}
	for name, mount := range map[string]MountConfig{
		"directory base": Mount.Owned(OwnedVolumeOptions{BasePath: "/srv/bases/app.raw"}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateOwnedMounts(map[string]MountConfig{"/data": mount}); err == nil {
				t.Fatal("expected a base on directory storage to fail before the native library")
			}
		})
	}
	if err := validateOwnedMounts(map[string]MountConfig{
		"/data": Mount.Owned(OwnedVolumeOptions{Kind: VolumeKindDisk, BasePath: "/srv/bases/app.raw"}),
		"/sized": Mount.Owned(OwnedVolumeOptions{
			Kind: VolumeKindDisk, BasePath: "/srv/bases/app.raw", SizeMiB: 256,
		}),
	}); err != nil {
		t.Fatalf("valid owned disks over a base rejected: %v", err)
	}
}
