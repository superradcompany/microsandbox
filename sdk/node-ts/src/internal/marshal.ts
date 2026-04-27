import type { VolumeMount } from "../mount.js";
import type { Patch } from "../patch.js";
import type { RegistryAuth } from "../registry.js";
import type { NetworkPolicy, Rule, Destination, PortRange } from "../policy/types.js";
import type { NetworkConfig as TsNetworkConfig } from "../network-config.js";
import type {
  NapiDnsConfig,
  NapiMountConfig,
  NapiNetworkConfig,
  NapiPatchConfig,
  NapiPolicyRule,
  NapiRegistryConfig,
  NapiSecretEntry,
  NapiTlsConfig,
} from "./napi.js";

export function mountToNapi(m: VolumeMount): NapiMountConfig {
  switch (m.kind) {
    case "bind":
      return { bind: m.host, readonly: m.readonly };
    case "named":
      return { named: m.name, readonly: m.readonly };
    case "tmpfs":
      return {
        tmpfs: true,
        sizeMib: m.sizeMib ?? undefined,
        readonly: m.readonly,
      };
    case "disk":
      return {
        disk: m.host,
        format: m.format,
        fstype: m.fstype ?? undefined,
        readonly: m.readonly,
      };
  }
}

export function patchToNapi(p: Patch): NapiPatchConfig {
  switch (p.kind) {
    case "text":
      return {
        kind: "text",
        path: p.path,
        content: p.content,
        mode: p.mode,
        replace: p.replace,
      };
    case "file":
      // The native binding expects `content` as a string; encode bytes as
      // utf-8 if we ever ship a binary-safe path, this is the place to
      // change it.
      return {
        kind: "file",
        path: p.path,
        content: Buffer.from(p.content).toString("base64"),
        mode: p.mode,
        replace: p.replace,
      };
    case "copyFile":
      return {
        kind: "copyFile",
        src: p.src,
        dst: p.dst,
        mode: p.mode,
        replace: p.replace,
      };
    case "copyDir":
      return { kind: "copyDir", src: p.src, dst: p.dst, replace: p.replace };
    case "symlink":
      return {
        kind: "symlink",
        target: p.target,
        link: p.link,
        replace: p.replace,
      };
    case "mkdir":
      return { kind: "mkdir", path: p.path, mode: p.mode };
    case "remove":
      return { kind: "remove", path: p.path };
    case "append":
      return { kind: "append", path: p.path, content: p.content };
  }
}

export function registryAuthToNapi(
  auth: RegistryAuth,
): NapiRegistryConfig["auth"] {
  if (auth.kind === "anonymous") return undefined;
  return { username: auth.username, password: auth.password };
}

/**
 * Render a `Destination` into the legacy single-string form the current
 * NAPI binding expects. The newer Rust schema is richer, but the binding
 * still consumes the flat representation.
 */
function destinationToString(d: Destination): string {
  switch (d.kind) {
    case "any":
      return "*";
    case "cidr":
      return d.cidr;
    case "domain":
      return d.domain;
    case "domainSuffix":
      return d.suffix.startsWith(".") ? d.suffix : `.${d.suffix}`;
    case "group":
      return d.group;
  }
}


function portRangesToStrings(ranges: readonly PortRange[]): string[] {
  return ranges.map((r) =>
    r.start === r.end ? String(r.start) : `${r.start}-${r.end}`,
  );
}

function ruleToNapi(rule: Rule): NapiPolicyRule {
  const out: NapiPolicyRule = {
    action: rule.action,
    direction: rule.direction,
    destination: destinationToString(rule.destination),
  };
  if (rule.protocols.length > 0) {
    out.protocols = rule.protocols.slice();
  }
  if (rule.ports.length > 0) {
    out.ports = portRangesToStrings(rule.ports);
  }
  return out;
}

export function networkPolicyToNapi(policy: NetworkPolicy): NapiNetworkConfig {
  return {
    rules: policy.rules.map(ruleToNapi),
    defaultEgress: policy.defaultEgress,
    defaultIngress: policy.defaultIngress,
  };
}

function dnsConfigToNapi(dns: TsNetworkConfig["dns"]): NapiDnsConfig | undefined {
  if (!dns) return undefined;
  const out: NapiDnsConfig = {};
  if (dns.blockedDomains.length > 0) out.blockDomains = dns.blockedDomains.slice();
  if (dns.blockedSuffixes.length > 0) {
    out.blockDomainSuffixes = dns.blockedSuffixes.slice();
  }
  if (dns.nameservers.length > 0) out.nameservers = dns.nameservers.slice();
  if (dns.rebindProtection !== null) out.rebindProtection = dns.rebindProtection;
  if (dns.queryTimeoutMs !== null) out.queryTimeoutMs = dns.queryTimeoutMs;
  return Object.keys(out).length > 0 ? out : undefined;
}

function tlsConfigToNapi(tls: TsNetworkConfig["tls"]): NapiTlsConfig | undefined {
  if (!tls) return undefined;
  const out: NapiTlsConfig = {};
  if (tls.bypass.length > 0) out.bypass = tls.bypass.slice();
  if (tls.verifyUpstream !== null) out.verifyUpstream = tls.verifyUpstream;
  if (tls.interceptedPorts.length > 0) {
    out.interceptedPorts = tls.interceptedPorts.slice();
  }
  if (tls.blockQuic !== null) out.blockQuic = tls.blockQuic;
  if (tls.upstreamCaCertPaths.length > 0) {
    out.upstreamCaCert = tls.upstreamCaCertPaths.slice();
  }
  if (tls.interceptCaCertPath) out.interceptCaCert = tls.interceptCaCertPath;
  if (tls.interceptCaKeyPath) out.interceptCaKey = tls.interceptCaKeyPath;
  return Object.keys(out).length > 0 ? out : undefined;
}

export function secretEntryToNapi(s: TsNetworkConfig["secrets"][number]): NapiSecretEntry {
  return {
    envVar: s.envVar,
    value: s.value,
    placeholder: s.placeholder ?? undefined,
    allowHosts: s.allowedHosts.length > 0 ? s.allowedHosts.slice() : undefined,
    allowHostPatterns:
      s.allowedHostPatterns.length > 0
        ? s.allowedHostPatterns.slice()
        : undefined,
    requireTls: s.requireTlsIdentity,
    inject:
      Object.keys(s.injection).length > 0
        ? {
            headers: s.injection.headers,
            basicAuth: s.injection.basicAuth,
            queryParams: s.injection.queryParams,
            body: s.injection.body,
          }
        : undefined,
  };
}

export function networkConfigToNapi(
  net: TsNetworkConfig,
): NapiNetworkConfig | undefined {
  if (!net.enabled) {
    // No way to express "off" via the legacy NetworkConfig — the binding
    // treats absence of network as default. The proper "no network" knob
    // lives on `SandboxBuilder.disableNetwork()` and is set on the
    // SandboxConfig level.
    return undefined;
  }

  const out: NapiNetworkConfig = {};
  if (net.policy) {
    out.rules = net.policy.rules.map(ruleToNapi);
    out.defaultEgress = net.policy.defaultEgress;
    out.defaultIngress = net.policy.defaultIngress;
  }
  const dns = dnsConfigToNapi(net.dns);
  if (dns) out.dns = dns;
  const tls = tlsConfigToNapi(net.tls);
  if (tls) out.tls = tls;
  if (net.maxConnections !== null) out.maxConnections = net.maxConnections;
  if (net.trustHostCAs) out.trustHostCas = true;

  return Object.keys(out).length > 0 ? out : undefined;
}
