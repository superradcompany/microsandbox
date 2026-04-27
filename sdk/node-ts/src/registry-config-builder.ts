import type { RegistryAuth } from "./registry.js";

/** Internal config produced by `RegistryConfigBuilder.build()`. */
export interface RegistryConfig {
  auth: RegistryAuth | null;
  insecure: boolean;
  caCertsPath: string | null;
}

export class RegistryConfigBuilder {
  private _auth: RegistryAuth | null = null;
  private _insecure = false;
  private _caCertsPath: string | null = null;

  auth(auth: RegistryAuth): this {
    this._auth = auth;
    return this;
  }

  /** Use plain HTTP for the registry. */
  insecure(): this {
    this._insecure = true;
    return this;
  }

  /** Path to a PEM file with extra root CAs to trust. */
  caCertsPath(path: string): this {
    this._caCertsPath = path;
    return this;
  }

  /** @internal */
  build(): RegistryConfig {
    return {
      auth: this._auth,
      insecure: this._insecure,
      caCertsPath: this._caCertsPath,
    };
  }
}
