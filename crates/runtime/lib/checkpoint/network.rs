//! Captured guest-visible network identity, independent of host allocation slots.

use microsandbox_image::checkpoint::ResourceDescriptor;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Historical artifacts have no CA evidence. For newer TLS captures, reject
/// malformed digests instead of accidentally treating them as missing evidence.
#[cfg(any(feature = "runner", feature = "net"))]
pub(super) fn intercept_ca_requirement(
    resources: &[ResourceDescriptor],
) -> Result<Option<String>, String> {
    let mut networks = resources
        .iter()
        .filter(|resource| resource.kind == "network");
    let identity = networks
        .next()
        .and_then(|network| network.binding.get("intercept_ca_sha256"));
    if networks.next().is_some() {
        return Err("checkpoint contains more than one guest network resource".into());
    }
    if let Some(value) = identity
        && (value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Err("invalid captured interception CA fingerprint".into());
    }
    Ok(identity.cloned())
}

#[cfg(any(feature = "runner", feature = "net"))]
pub(super) fn validate_intercept_ca(
    required: Option<&str>,
    destination: Option<&str>,
) -> Result<(), String> {
    if let Some(fingerprint) = required
        && destination != required
    {
        return Err(format!(
            "full restore requires the captured TLS interception CA (SHA-256 {fingerprint}); the destination proxy has a different or missing signing identity"
        ));
    }
    Ok(())
}

/// Read the gateway Ethernet identity retained by guest ARP/ND caches.
///
/// A fresh proxy owns fresh host sockets, but must present the same virtual
/// gateway to captured RAM. Missing identity is not safely reconstructible
/// from a guest MAC or IP: both may have explicit user overrides.
pub fn captured_gateway_mac(resources: &[ResourceDescriptor]) -> Result<Option<[u8; 6]>, String> {
    let mut networks = resources
        .iter()
        .filter(|resource| resource.kind == "network");
    let Some(network) = networks.next() else {
        return Ok(None);
    };
    if networks.next().is_some() {
        return Err("checkpoint contains more than one guest network resource".into());
    }
    let value = network.binding.get("gateway_mac").ok_or_else(|| {
        "checkpoint lacks captured gateway MAC; recapture this development full snapshot"
            .to_string()
    })?;
    let mac: [u8; 6] = serde_json::from_str(value)
        .map_err(|error| format!("invalid captured gateway MAC: {error}"))?;
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return Err("captured gateway MAC must be a nonzero unicast address".into());
    }
    Ok(Some(mac))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use microsandbox_image::checkpoint::ResourceTreatment;

    use super::*;

    fn resource(value: Option<&str>) -> ResourceDescriptor {
        ResourceDescriptor {
            id: "virtio:1:net".into(),
            kind: "network".into(),
            treatment: ResourceTreatment::Reconnect,
            binding: value
                .map(|value| BTreeMap::from([("gateway_mac".into(), value.into())]))
                .unwrap_or_default(),
        }
    }

    #[cfg(any(feature = "runner", feature = "net"))]
    #[test]
    fn captured_tls_requires_the_actual_proxy_identity() {
        let mut network = resource(None);
        let fingerprint = "13".repeat(32);
        assert_eq!(intercept_ca_requirement(&[network.clone()]).unwrap(), None);
        assert!(validate_intercept_ca(None, None).is_ok());
        network
            .binding
            .insert("intercept_ca_sha256".into(), fingerprint.clone());
        let required = intercept_ca_requirement(&[network.clone()]).unwrap();
        assert!(validate_intercept_ca(required.as_deref(), Some(&fingerprint)).is_ok());
        assert!(validate_intercept_ca(required.as_deref(), None).is_err());
        assert!(validate_intercept_ca(required.as_deref(), Some(&"23".repeat(32))).is_err());
        network
            .binding
            .insert("intercept_ca_sha256".into(), "../different-ca".into());
        assert!(intercept_ca_requirement(&[network]).is_err());
    }

    #[test]
    fn captured_gateway_identity_is_required_only_for_networked_checkpoints() {
        assert_eq!(captured_gateway_mac(&[]).unwrap(), None);
        assert!(
            captured_gateway_mac(&[resource(None)])
                .unwrap_err()
                .contains("recapture")
        );
        assert_eq!(
            captured_gateway_mac(&[resource(Some("[2,109,115,0,7,1]"))]).unwrap(),
            Some([2, 109, 115, 0, 7, 1])
        );
    }

    #[test]
    fn captured_gateway_identity_rejects_invalid_and_duplicate_bindings() {
        for value in ["garbage", "[2,1]", "[0,0,0,0,0,0]", "[1,0,0,0,0,1]"] {
            assert!(captured_gateway_mac(&[resource(Some(value))]).is_err());
        }
        let network = resource(Some("[2,109,115,0,7,1]"));
        assert!(captured_gateway_mac(&[network.clone(), network]).is_err());
    }
}
