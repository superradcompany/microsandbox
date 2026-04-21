//! Collect the host's trusted root CAs as a PEM bundle.
//!
//! Used by [`SmoltcpNetwork::host_cas_cert_pem`] to ship the host's extra
//! CAs into the guest so outbound TLS works behind corporate MITM proxies
//! (Cloudflare Warp Zero Trust, Zscaler, Netskope, etc.) whose gateway CA
//! is trusted on the host but unknown to the guest.
//!
//! What this ships: only trust roots from the host's keychain / system
//! trust store, deduplicated by DER. `rustls_native_certs` is a
//! roots-only API — it reads certificates marked trusted for SSL
//! (macOS System/SystemRoots/login keychains; `/etc/ssl/certs` on
//! Linux) and never returns private keys or end-entity certs.
//!
//! We ship *everything* the host trusts, not a delta against Mozilla's
//! root bundle. The guest already trusts the Mozilla set natively;
//! appending duplicates is harmless (trust is a set, not a list). Skipping
//! the delta avoids pulling `webpki-roots` and keeps the code trivial.
//!
//! [`SmoltcpNetwork::host_cas_cert_pem`]: super::super::network::SmoltcpNetwork::host_cas_cert_pem

use std::collections::HashSet;

use pem::{EncodeConfig, LineEnding, Pem};

/// PEM block tag for a trust-root certificate. We only ever emit this
/// tag; the bundle is constrained to public certs by both the input API
/// (`rustls_native_certs` returns DER-encoded certs only) and by the
/// encoder here, so no private-key material can leak into the guest.
const CERTIFICATE_TAG: &str = "CERTIFICATE";

/// Collect the host's trusted root CAs as a concatenated PEM bundle.
///
/// Deduplicates by DER bytes so macOS hosts, where the same root may
/// appear in multiple keychains (System, SystemRoots, login), don't ship
/// duplicated entries to the guest. Returns `None` if the host store has
/// no usable certs. Loader errors are logged (not returned) so one bad
/// entry does not fail the whole collection.
pub(crate) fn collect_host_cas() -> Option<Vec<u8>> {
    let result = rustls_native_certs::load_native_certs();
    let error_count = result.errors.len();

    let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(result.certs.len());
    let mut pems: Vec<Pem> = Vec::with_capacity(result.certs.len());
    for cert in result.certs {
        let der = cert.as_ref().to_vec();
        if seen.insert(der.clone()) {
            pems.push(Pem::new(CERTIFICATE_TAG, der));
        }
    }

    tracing::info!(
        imported = pems.len(),
        errors = error_count,
        "collected host CAs for guest trust store"
    );

    if pems.is_empty() {
        return None;
    }

    let encoded =
        pem::encode_many_config(&pems, EncodeConfig::new().set_line_ending(LineEnding::LF));
    Some(encoded.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_host_cas_returns_parseable_bundle() {
        // The host running this test has *some* trust store — any modern
        // macOS / Linux dev machine does. If this returns `None`, the test
        // is uninformative, not wrong; skip.
        let Some(bundle) = collect_host_cas() else {
            eprintln!("host has no trusted CAs; skipping roundtrip check");
            return;
        };

        let parsed = pem::parse_many(&bundle).expect("bundle parses");
        assert!(!parsed.is_empty(), "bundle contains at least one cert");

        // Every block must be a CERTIFICATE — no private keys allowed to
        // slip through under any tag.
        for p in &parsed {
            assert_eq!(p.tag(), CERTIFICATE_TAG);
            assert!(!p.contents().is_empty(), "cert body is non-empty");
        }

        // DER dedup: no two entries should share the same body bytes.
        let mut seen = HashSet::new();
        for p in &parsed {
            assert!(
                seen.insert(p.contents().to_vec()),
                "bundle contains a duplicated cert"
            );
        }
    }
}
