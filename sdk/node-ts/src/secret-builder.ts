import { InvalidConfigError } from "./errors.js";
import type { SecretEntry, SecretInjection } from "./network-config.js";

export class SecretBuilder {
  private _envVar: string | null = null;
  private _value: string | null = null;
  private _placeholder: string | null = null;
  private _allowedHosts: string[] = [];
  private _allowedHostPatterns: string[] = [];
  private _allowAnyHost = false;
  private _requireTlsIdentity = true;
  private _injection: SecretInjection = {};

  /** Environment variable to expose the placeholder under. Required. */
  env(varName: string): this {
    this._envVar = varName;
    return this;
  }

  /** The real secret value (stays on the host). Required. */
  value(value: string): this {
    this._value = value;
    return this;
  }

  /** Custom placeholder string. Auto-generated as `$MSB_<ENV_VAR>` if omitted. */
  placeholder(placeholder: string): this {
    this._placeholder = placeholder;
    return this;
  }

  /** Allow substitution to a specific host. */
  allowHost(host: string): this {
    this._allowedHosts.push(host);
    return this;
  }

  /** Allow substitution to any host matching a wildcard pattern. */
  allowHostPattern(pattern: string): this {
    this._allowedHostPatterns.push(pattern);
    return this;
  }

  /** Permit substitution to any host. Acknowledge the risk explicitly. */
  allowAnyHostDangerous(iUnderstandTheRisk: boolean): this {
    this._allowAnyHost = iUnderstandTheRisk;
    return this;
  }

  /** Require a verified TLS identity before substituting. Default true. */
  requireTlsIdentity(enabled: boolean): this {
    this._requireTlsIdentity = enabled;
    return this;
  }

  /** Allow substitution in HTTP headers. Default true. */
  injectHeaders(enabled: boolean): this {
    this._injection = { ...this._injection, headers: enabled };
    return this;
  }

  /** Allow substitution in the HTTP Basic Auth credential. Default true. */
  injectBasicAuth(enabled: boolean): this {
    this._injection = { ...this._injection, basicAuth: enabled };
    return this;
  }

  /** Allow substitution in URL query parameters. Default false. */
  injectQuery(enabled: boolean): this {
    this._injection = { ...this._injection, queryParams: enabled };
    return this;
  }

  /** Allow substitution in the HTTP request body. Default false. */
  injectBody(enabled: boolean): this {
    this._injection = { ...this._injection, body: enabled };
    return this;
  }

  /** @internal */
  build(): SecretEntry {
    if (this._envVar === null) {
      throw new InvalidConfigError("SecretBuilder: .env(varName) is required");
    }
    if (this._value === null) {
      throw new InvalidConfigError("SecretBuilder: .value(value) is required");
    }
    return {
      envVar: this._envVar,
      value: this._value,
      placeholder: this._placeholder,
      allowedHosts: this._allowedHosts.slice(),
      allowedHostPatterns: this._allowedHostPatterns.slice(),
      allowAnyHost: this._allowAnyHost,
      requireTlsIdentity: this._requireTlsIdentity,
      injection: { ...this._injection },
    };
  }
}
