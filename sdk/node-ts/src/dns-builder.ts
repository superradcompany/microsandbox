import type { DnsConfig } from "./network-config.js";

export class DnsBuilder {
  private _blockedDomains: string[] = [];
  private _blockedSuffixes: string[] = [];
  private _nameservers: string[] = [];
  private _rebindProtection: boolean | null = null;
  private _queryTimeoutMs: number | null = null;

  /** Block a specific FQDN (returns REFUSED). */
  blockDomain(domain: string): this {
    this._blockedDomains.push(domain);
    return this;
  }

  /** Block any name ending in `suffix`. */
  blockDomainSuffix(suffix: string): this {
    this._blockedSuffixes.push(suffix);
    return this;
  }

  /** Override the upstream nameservers (`IP`, `IP:PORT`, `HOST`, or `HOST:PORT`). */
  nameservers(servers: Iterable<string>): this {
    for (const s of servers) this._nameservers.push(s);
    return this;
  }

  /** Toggle DNS rebinding protection. */
  rebindProtection(enabled: boolean): this {
    this._rebindProtection = enabled;
    return this;
  }

  /** Per-query timeout in milliseconds. */
  queryTimeoutMs(ms: number): this {
    this._queryTimeoutMs = ms;
    return this;
  }

  /** @internal */
  build(): DnsConfig {
    return {
      blockedDomains: this._blockedDomains.slice(),
      blockedSuffixes: this._blockedSuffixes.slice(),
      nameservers: this._nameservers.slice(),
      rebindProtection: this._rebindProtection,
      queryTimeoutMs: this._queryTimeoutMs,
    };
  }
}
