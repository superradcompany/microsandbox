package microsandbox

import (
	"context"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Image is the factory namespace for OCI image-cache operations. It mirrors
// the Node `Image` class and the Python `Image` static methods.
//
//	microsandbox.Image.List(ctx)
//	microsandbox.Image.Inspect(ctx, "python:3.12")
//	microsandbox.Image.Remove(ctx, "old:tag", true)
var Image imageFactory

type imageFactory struct{}

// Get fetches a single cached image by reference. Returns ErrImageNotFound
// when no image is present in the cache.
func (imageFactory) Get(ctx context.Context, reference string) (*ImageHandle, error) {
	info, err := ffi.ImageGet(ctx, reference)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return imageHandleFromInfo(info), nil
}

// List returns every cached image, ordered by creation time (newest first).
func (imageFactory) List(ctx context.Context) ([]*ImageHandle, error) {
	infos, err := ffi.ImageList(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	out := make([]*ImageHandle, len(infos))
	for i, info := range infos {
		out[i] = imageHandleFromInfo(info)
	}
	return out, nil
}

// Inspect returns the full detail (handle + parsed OCI config + layer list)
// for a cached image.
func (imageFactory) Inspect(ctx context.Context, reference string) (*ImageDetail, error) {
	info, err := ffi.ImageInspect(ctx, reference)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return imageDetailFromInfo(info), nil
}

// Remove deletes a cached image. When force=false, sandboxes that still
// reference the image cause the call to fail with ErrImageInUse.
func (imageFactory) Remove(ctx context.Context, reference string, force bool) error {
	return wrapFFI(ffi.ImageRemove(ctx, reference, force))
}

// GCLayers garbage-collects orphaned layers (no manifest references) and
// returns the count of layers reclaimed.
func (imageFactory) GCLayers(ctx context.Context) (uint32, error) {
	n, err := ffi.ImageGCLayers(ctx)
	return n, wrapFFI(err)
}

// GC garbage-collects everything reclaimable in the image cache and
// returns the count of records reclaimed.
func (imageFactory) GC(ctx context.Context) (uint32, error) {
	n, err := ffi.ImageGC(ctx)
	return n, wrapFFI(err)
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// ImageHandle is a lightweight metadata reference to a cached OCI image.
// Obtain via Image.Get / Image.List.
type ImageHandle struct {
	reference      string
	manifestDigest string
	architecture   string
	os             string
	layerCount     uint
	sizeBytes      *int64
	createdAtUnix  *int64
	lastUsedAtUnix *int64
}

func imageHandleFromInfo(info *ffi.ImageHandleInfo) *ImageHandle {
	return &ImageHandle{
		reference:      info.Reference,
		manifestDigest: info.ManifestDigest,
		architecture:   info.Architecture,
		os:             info.OS,
		layerCount:     info.LayerCount,
		sizeBytes:      info.SizeBytes,
		createdAtUnix:  info.CreatedAtUnix,
		lastUsedAtUnix: info.LastUsedAtUnix,
	}
}

// Reference returns the image reference (e.g. "docker.io/library/python:3.12").
func (h *ImageHandle) Reference() string { return h.reference }

// ManifestDigest returns the content-addressable manifest digest, or empty.
func (h *ImageHandle) ManifestDigest() string { return h.manifestDigest }

// Architecture returns the architecture resolved during pull, or empty.
func (h *ImageHandle) Architecture() string { return h.architecture }

// OS returns the operating system resolved during pull, or empty.
func (h *ImageHandle) OS() string { return h.os }

// LayerCount returns the number of layers in the image.
func (h *ImageHandle) LayerCount() uint { return h.layerCount }

// SizeBytes returns the total image size in bytes, or nil if unknown.
func (h *ImageHandle) SizeBytes() *int64 { return h.sizeBytes }

// CreatedAt returns when this image was first pulled, or the zero value.
func (h *ImageHandle) CreatedAt() time.Time {
	if h.createdAtUnix == nil {
		return time.Time{}
	}
	return time.Unix(*h.createdAtUnix, 0)
}

// LastUsedAt returns when this image was last referenced, or the zero value.
func (h *ImageHandle) LastUsedAt() time.Time {
	if h.lastUsedAtUnix == nil {
		return time.Time{}
	}
	return time.Unix(*h.lastUsedAtUnix, 0)
}

// Remove deletes this image. When force=false, sandboxes that still
// reference the image cause the call to fail with ErrImageInUse.
func (h *ImageHandle) Remove(ctx context.Context, force bool) error {
	return Image.Remove(ctx, h.reference, force)
}

// Inspect returns the full detail for this image.
func (h *ImageHandle) Inspect(ctx context.Context) (*ImageDetail, error) {
	return Image.Inspect(ctx, h.reference)
}

// ImageDetail bundles a handle with the parsed OCI config and layer list.
type ImageDetail struct {
	*ImageHandle
	Config *ImageConfig
	Layers []ImageLayer
}

// ImageConfig is the parsed OCI config block.
type ImageConfig struct {
	Digest     string
	Env        []string
	Cmd        []string
	Entrypoint []string
	WorkingDir string
	User       string
	Labels     map[string]string
	StopSignal string
}

// ImageLayer is one layer of an image manifest.
type ImageLayer struct {
	DiffID              string
	BlobDigest          string
	MediaType           string
	CompressedSizeBytes *int64
	ErofsSizeBytes      *int64
	Position            int32
}

func imageDetailFromInfo(info *ffi.ImageDetailInfo) *ImageDetail {
	d := &ImageDetail{ImageHandle: imageHandleFromInfo(&info.ImageHandleInfo)}
	if info.Config != nil {
		d.Config = &ImageConfig{
			Digest:     info.Config.Digest,
			Env:        info.Config.Env,
			Cmd:        info.Config.Cmd,
			Entrypoint: info.Config.Entrypoint,
			WorkingDir: info.Config.WorkingDir,
			User:       info.Config.User,
			Labels:     info.Config.Labels,
			StopSignal: info.Config.StopSignal,
		}
	}
	if len(info.Layers) > 0 {
		d.Layers = make([]ImageLayer, len(info.Layers))
		for i, l := range info.Layers {
			d.Layers[i] = ImageLayer{
				DiffID:              l.DiffID,
				BlobDigest:          l.BlobDigest,
				MediaType:           l.MediaType,
				CompressedSizeBytes: l.CompressedSizeBytes,
				ErofsSizeBytes:      l.ErofsSizeBytes,
				Position:            l.Position,
			}
		}
	}
	return d
}
