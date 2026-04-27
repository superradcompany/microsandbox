import { withMappedErrors } from "./internal/error-mapping.js";
import { mapAsyncIterable } from "./internal/async-iter.js";
import type {
  NapiFsEntry,
  NapiFsMetadata,
  NapiFsReadStream,
  NapiFsWriteSink,
  NapiSandboxFs,
} from "./internal/napi.js";
import type { FsEntry, FsEntryKind, FsMetadata } from "./fs-types.js";

export class FsReadStream
  implements AsyncIterable<Uint8Array>, AsyncDisposable
{
  private readonly inner: NapiFsReadStream;
  private done = false;

  /** @internal */
  constructor(inner: NapiFsReadStream) {
    this.inner = inner;
  }

  async recv(): Promise<Uint8Array | null> {
    if (this.done) return null;
    const buf = await withMappedErrors(() => this.inner.recv());
    if (buf === null) {
      this.done = true;
      return null;
    }
    return new Uint8Array(buf);
  }

  /** Drain the stream into a single buffer. */
  async collect(): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const c = await this.recv();
      if (c === null) break;
      chunks.push(c);
      total += c.byteLength;
    }
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      out.set(c, off);
      off += c.byteLength;
    }
    return out;
  }

  [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
    return mapAsyncIterable<Buffer, Uint8Array>(
      { recv: () => this.inner.recv() },
      (buf) => new Uint8Array(buf),
    )[Symbol.asyncIterator]();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    this.done = true;
  }
}

export class FsWriteSink implements AsyncDisposable {
  private readonly inner: NapiFsWriteSink;
  private closed = false;

  /** @internal */
  constructor(inner: NapiFsWriteSink) {
    this.inner = inner;
  }

  async write(data: Uint8Array | string): Promise<void> {
    const buf =
      typeof data === "string"
        ? Buffer.from(data, "utf8")
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    await withMappedErrors(() => this.inner.write(buf));
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await withMappedErrors(() => this.inner.close());
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }
}

export class SandboxFs {
  private readonly inner: NapiSandboxFs;

  /** @internal */
  constructor(inner: NapiSandboxFs) {
    this.inner = inner;
  }

  async read(path: string): Promise<Uint8Array> {
    const buf = await withMappedErrors(() => this.inner.read(path));
    return new Uint8Array(buf);
  }

  async readToString(path: string): Promise<string> {
    return await withMappedErrors(() => this.inner.readString(path));
  }

  async readStream(path: string): Promise<FsReadStream> {
    const raw = await withMappedErrors(() => this.inner.readStream(path));
    return new FsReadStream(raw);
  }

  async writeStream(path: string): Promise<FsWriteSink> {
    const raw = await withMappedErrors(() => this.inner.writeStream(path));
    return new FsWriteSink(raw);
  }

  async write(path: string, data: Uint8Array | string): Promise<void> {
    const buf =
      typeof data === "string"
        ? Buffer.from(data, "utf8")
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    await withMappedErrors(() => this.inner.write(path, buf));
  }

  async list(path: string): Promise<FsEntry[]> {
    const entries = await withMappedErrors(() => this.inner.list(path));
    return entries.map(napiFsEntryToFsEntry);
  }

  async mkdir(path: string): Promise<void> {
    await withMappedErrors(() => this.inner.mkdir(path));
  }

  async removeDir(path: string): Promise<void> {
    await withMappedErrors(() => this.inner.removeDir(path));
  }

  async remove(path: string): Promise<void> {
    await withMappedErrors(() => this.inner.remove(path));
  }

  async copy(from: string, to: string): Promise<void> {
    await withMappedErrors(() => this.inner.copy(from, to));
  }

  async rename(from: string, to: string): Promise<void> {
    await withMappedErrors(() => this.inner.rename(from, to));
  }

  async stat(path: string): Promise<FsMetadata> {
    const meta = await withMappedErrors(() => this.inner.stat(path));
    return napiFsMetadataToFsMetadata(meta);
  }

  async exists(path: string): Promise<boolean> {
    return await withMappedErrors(() => this.inner.exists(path));
  }

  /** Copy a host file into the guest. */
  async copyFromHost(hostPath: string, guestPath: string): Promise<void> {
    await withMappedErrors(() =>
      this.inner.copyFromHost(hostPath, guestPath),
    );
  }

  /** Copy a guest file out to the host. */
  async copyToHost(guestPath: string, hostPath: string): Promise<void> {
    await withMappedErrors(() =>
      this.inner.copyToHost(guestPath, hostPath),
    );
  }
}

function napiFsEntryToFsEntry(e: NapiFsEntry): FsEntry {
  return {
    path: e.path,
    kind: e.kind as FsEntryKind,
    size: e.size,
    mode: e.mode,
    modified: typeof e.modified === "number" ? new Date(e.modified) : null,
  };
}

function napiFsMetadataToFsMetadata(m: NapiFsMetadata): FsMetadata {
  return {
    kind: m.kind as FsEntryKind,
    size: m.size,
    mode: m.mode,
    readonly: m.readonly,
    modified: typeof m.modified === "number" ? new Date(m.modified) : null,
    created: typeof m.created === "number" ? new Date(m.created) : null,
  };
}
