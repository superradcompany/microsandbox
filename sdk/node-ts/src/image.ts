import { withMappedErrors } from "./internal/error-mapping.js";
import { napi } from "./internal/napi.js";
import type {
  NapiImageConfigDetail,
  NapiImageDetail,
  NapiImageHandle,
  NapiImageInfo,
  NapiImageLayerDetail,
} from "./internal/napi.js";

export interface ImageConfigDetail {
  readonly digest: string;
  readonly env: readonly string[];
  readonly cmd: readonly string[] | null;
  readonly entrypoint: readonly string[] | null;
  readonly workingDir: string | null;
  readonly user: string | null;
  readonly labels: Record<string, unknown> | null;
  readonly stopSignal: string | null;
}

export interface ImageLayerDetail {
  readonly diffId: string;
  readonly blobDigest: string;
  readonly mediaType: string | null;
  readonly compressedSizeBytes: number | null;
  readonly erofsSizeBytes: number | null;
  readonly position: number;
}

export interface ImageDetail {
  readonly handle: ImageHandle;
  readonly config: ImageConfigDetail | null;
  readonly layers: readonly ImageLayerDetail[];
}

export interface ImagePruneReport {
  readonly imageRefsRemoved: number;
  readonly manifestsRemoved: number;
  readonly layersRemoved: number;
  readonly fsmetaRemoved: number;
  readonly vmdkRemoved: number;
  readonly bytesReclaimed: number | null;
}

export class ImageHandle {
  readonly reference: string;
  readonly sizeBytes: number | null;
  readonly manifestDigest: string | null;
  readonly architecture: string | null;
  readonly os: string | null;
  readonly layerCount: number;
  readonly lastUsedAt: Date | null;
  readonly createdAt: Date | null;

  /** @internal */
  constructor(raw: NapiImageHandle | NapiImageInfo) {
    this.reference = raw.reference;
    this.sizeBytes = numOrNull(raw.sizeBytes);
    this.manifestDigest = strOrNull(raw.manifestDigest);
    this.architecture = strOrNull(raw.architecture);
    this.os = strOrNull(raw.os);
    this.layerCount = raw.layerCount;
    this.lastUsedAt = msToDate(raw.lastUsedAt);
    this.createdAt = msToDate(raw.createdAt);
  }
}

export class Image {
  /** Look up a cached image by reference. */
  static async get(reference: string): Promise<ImageHandle> {
    const raw = await withMappedErrors(() => napi.imageGet(reference));
    return new ImageHandle(raw);
  }

  /** List all cached images. */
  static async list(): Promise<ImageHandle[]> {
    const infos = await withMappedErrors(() => napi.imageList());
    return infos.map((i) => new ImageHandle(i));
  }

  /** Full inspect (config + layers). */
  static async inspect(reference: string): Promise<ImageDetail> {
    const raw = await withMappedErrors(() => napi.imageInspect(reference));
    return imageDetailFromNapi(raw);
  }

  /**
   * Remove a cached image. Pass `force: true` to delete even when a
   * sandbox references it.
   */
  static async remove(
    reference: string,
    opts: { force?: boolean } = {},
  ): Promise<void> {
    await withMappedErrors(() => napi.imageRemove(reference, opts.force));
  }

  /** Remove cached image data that is not used by sandboxes. */
  static async prune(): Promise<ImagePruneReport> {
    const raw = await withMappedErrors(() => napi.imagePrune());
    return {
      imageRefsRemoved: raw.imageRefsRemoved,
      manifestsRemoved: raw.manifestsRemoved,
      layersRemoved: raw.layersRemoved,
      fsmetaRemoved: raw.fsmetaRemoved,
      vmdkRemoved: raw.vmdkRemoved,
      bytesReclaimed: numOrNull(raw.bytesReclaimed),
    };
  }

  /**
   * Import images from a local archive (`docker save` tarball or OCI Image
   * Layout) into the cache. `tag` applies an extra reference to the first
   * image in the archive. Returns a handle for every reference imported.
   */
  static async load(
    inputPath: string,
    opts: { tag?: string } = {},
  ): Promise<ImageHandle[]> {
    const infos = await withMappedErrors(() =>
      napi.imageLoad(inputPath, opts.tag),
    );
    return infos.map((i) => new ImageHandle(i));
  }

  /**
   * Export one or more cached images to an archive file. `format` selects
   * the layout: `"docker"` (default, loadable with `docker load`) or
   * `"oci"` (OCI Image Layout).
   */
  static async save(
    reference: string | readonly string[],
    opts: { outputPath: string; format?: "docker" | "oci" },
  ): Promise<void> {
    const references = typeof reference === "string" ? [reference] : reference;
    await withMappedErrors(() =>
      napi.imageSave([...references], opts.outputPath, opts.format),
    );
  }
}

function numOrNull(v: number | null | undefined): number | null {
  return typeof v === "number" ? v : null;
}

function strOrNull(v: string | null | undefined): string | null {
  return typeof v === "string" ? v : null;
}

function msToDate(v: number | null | undefined): Date | null {
  return typeof v === "number" ? new Date(v) : null;
}

function imageConfigFromNapi(c: NapiImageConfigDetail): ImageConfigDetail {
  let labels: Record<string, unknown> | null = null;
  if (typeof c.labelsJson === "string") {
    try {
      labels = JSON.parse(c.labelsJson) as Record<string, unknown>;
    } catch {
      labels = null;
    }
  }
  return {
    digest: c.digest,
    env: c.env,
    cmd: c.cmd ?? null,
    entrypoint: c.entrypoint ?? null,
    workingDir: strOrNull(c.workingDir),
    user: strOrNull(c.user),
    labels,
    stopSignal: strOrNull(c.stopSignal),
  };
}

function imageLayerFromNapi(l: NapiImageLayerDetail): ImageLayerDetail {
  return {
    diffId: l.diffId,
    blobDigest: l.blobDigest,
    mediaType: strOrNull(l.mediaType),
    compressedSizeBytes: numOrNull(l.compressedSizeBytes),
    erofsSizeBytes: numOrNull(l.erofsSizeBytes),
    position: l.position,
  };
}

function imageDetailFromNapi(d: NapiImageDetail): ImageDetail {
  return {
    handle: new ImageHandle(d),
    config: d.config ? imageConfigFromNapi(d.config) : null,
    layers: d.layers.map(imageLayerFromNapi),
  };
}
