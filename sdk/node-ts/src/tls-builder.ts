import type { TlsConfig } from "./network-config.js";

export class TlsBuilder {
  private _bypass: string[] = [];
  private _verifyUpstream: boolean | null = null;
  private _interceptedPorts: number[] = [];
  private _blockQuic: boolean | null = null;
  private _upstreamCaPaths: string[] = [];
  private _interceptCaCert: string | null = null;
  private _interceptCaKey: string | null = null;

  /** Skip interception for hosts matching this glob (e.g. `"*.internal.corp"`). */
  bypass(pattern: string): this {
    this._bypass.push(pattern);
    return this;
  }

  /** Whether to verify upstream certificates (default: true). */
  verifyUpstream(verify: boolean): this {
    this._verifyUpstream = verify;
    return this;
  }

  /** TCP ports to intercept. Default `[443]`. */
  interceptedPorts(ports: Iterable<number>): this {
    for (const p of ports) this._interceptedPorts.push(p);
    return this;
  }

  /** Block QUIC on intercepted ports. */
  blockQuic(block: boolean): this {
    this._blockQuic = block;
    return this;
  }

  /** Path to a PEM file with extra root CAs the proxy should trust. */
  upstreamCaCert(path: string): this {
    this._upstreamCaPaths.push(path);
    return this;
  }

  /** Path to the PEM file used as the intercepting CA's certificate. */
  interceptCaCert(path: string): this {
    this._interceptCaCert = path;
    return this;
  }

  /** Path to the PEM file used as the intercepting CA's private key. */
  interceptCaKey(path: string): this {
    this._interceptCaKey = path;
    return this;
  }

  /** @internal */
  build(): TlsConfig {
    return {
      bypass: this._bypass.slice(),
      verifyUpstream: this._verifyUpstream,
      interceptedPorts: this._interceptedPorts.slice(),
      blockQuic: this._blockQuic,
      upstreamCaCertPaths: this._upstreamCaPaths.slice(),
      interceptCaCertPath: this._interceptCaCert,
      interceptCaKeyPath: this._interceptCaKey,
    };
  }
}
