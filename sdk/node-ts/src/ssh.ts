import type {
  NapiSandbox,
  NapiSshAttachOptions,
  NapiSshClient,
  NapiSshClientOptions,
  NapiSshExecOptions,
  NapiSshOutput,
  NapiSshServer,
  NapiSshServerOptions,
  NapiSftpClient,
} from "./internal/napi.js";
import { withMappedErrors } from "./internal/error-mapping.js";

export interface SshOutput {
  readonly status: number;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
}

export interface SshClientOptions {
  readonly user?: string;
  readonly term?: string;
  readonly sftp?: boolean;
}

export interface SshExecOptions {
  readonly tty?: boolean;
}

export interface SshAttachOptions {
  readonly term?: string;
  readonly detachKeys?: string;
}

export interface SshServerOptions {
  readonly hostKeyPath?: string;
  readonly authorizedKeysPath?: string;
  readonly user?: string;
  readonly sftp?: boolean;
}

export class SandboxSshOps {
  /** @internal */
  private readonly inner: NapiSandbox;

  /** @internal */
  constructor(inner: NapiSandbox) {
    this.inner = inner;
  }

  async openClient(opts?: SshClientOptions): Promise<SshClient> {
    const raw = await withMappedErrors(() =>
      this.inner.sshConnect(sshClientOptionsToNapi(opts)),
    );
    return new SshClient(raw);
  }

  async prepareServer(opts?: SshServerOptions): Promise<SshServer> {
    const raw = await withMappedErrors(() =>
      this.inner.sshServer(sshServerOptionsToNapi(opts)),
    );
    return new SshServer(raw);
  }
}

export class SshClient {
  /** @internal */
  private readonly inner: NapiSshClient;

  /** @internal */
  constructor(inner: NapiSshClient) {
    this.inner = inner;
  }

  async exec(command: string, opts?: SshExecOptions): Promise<SshOutput> {
    const output = await withMappedErrors(() =>
      this.inner.exec(command, sshExecOptionsToNapi(opts)),
    );
    return sshOutputFromNapi(output);
  }

  async attach(opts?: SshAttachOptions): Promise<number> {
    return await withMappedErrors(() =>
      this.inner.attach(sshAttachOptionsToNapi(opts)),
    );
  }

  async sftp(): Promise<SftpClient> {
    const raw = await withMappedErrors(() => this.inner.sftp());
    return new SftpClient(raw);
  }

  async close(): Promise<void> {
    await withMappedErrors(() => this.inner.close());
  }
}

export class SftpClient {
  /** @internal */
  private readonly inner: NapiSftpClient;

  /** @internal */
  constructor(inner: NapiSftpClient) {
    this.inner = inner;
  }

  async read(path: string): Promise<Buffer> {
    return await withMappedErrors(() => this.inner.read(path));
  }

  async write(path: string, data: Buffer): Promise<void> {
    await withMappedErrors(() => this.inner.write(path, data));
  }

  async mkdir(path: string): Promise<void> {
    await withMappedErrors(() => this.inner.mkdir(path));
  }

  async removeFile(path: string): Promise<void> {
    await withMappedErrors(() => this.inner.removeFile(path));
  }

  async removeDir(path: string): Promise<void> {
    await withMappedErrors(() => this.inner.removeDir(path));
  }

  async rename(oldPath: string, newPath: string): Promise<void> {
    await withMappedErrors(() => this.inner.rename(oldPath, newPath));
  }

  async realPath(path: string): Promise<string> {
    return await withMappedErrors(() => this.inner.realPath(path));
  }

  async readLink(path: string): Promise<string> {
    return await withMappedErrors(() => this.inner.readLink(path));
  }

  async symlink(target: string, linkPath: string): Promise<void> {
    await withMappedErrors(() => this.inner.symlink(target, linkPath));
  }

  async close(): Promise<void> {
    await withMappedErrors(() => this.inner.close());
  }
}

export class SshServer {
  /** @internal */
  private readonly inner: NapiSshServer;

  /** @internal */
  constructor(inner: NapiSshServer) {
    this.inner = inner;
  }

  async serveConnection(): Promise<void> {
    await withMappedErrors(() => this.inner.serveConnection());
  }

  async close(): Promise<void> {
    await withMappedErrors(() => this.inner.close());
  }
}

export function sshClientOptionsToNapi(
  opts?: SshClientOptions,
): NapiSshClientOptions | undefined {
  if (!opts) return undefined;
  return {
    user: opts.user,
    term: opts.term,
    sftp: opts.sftp,
  };
}

export function sshExecOptionsToNapi(
  opts?: SshExecOptions,
): NapiSshExecOptions | undefined {
  if (!opts) return undefined;
  return {
    tty: opts.tty,
  };
}

export function sshAttachOptionsToNapi(
  opts?: SshAttachOptions,
): NapiSshAttachOptions | undefined {
  if (!opts) return undefined;
  return {
    term: opts.term,
    detachKeys: opts.detachKeys,
  };
}

export function sshServerOptionsToNapi(
  opts?: SshServerOptions,
): NapiSshServerOptions | undefined {
  if (!opts) return undefined;
  return {
    hostKeyPath: opts.hostKeyPath,
    authorizedKeysPath: opts.authorizedKeysPath,
    user: opts.user,
    sftp: opts.sftp,
  };
}

function sshOutputFromNapi(output: NapiSshOutput): SshOutput {
  return {
    status: output.status,
    stdout: output.stdout,
    stderr: output.stderr,
  };
}
