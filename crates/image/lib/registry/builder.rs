use oci_client::{
    Client,
    client::{Certificate, CertificateEncoding, ClientConfig, ClientProtocol},
};

use crate::{
    auth::RegistryAuth,
    cache::GlobalCache,
    error::{ImageError, ImageResult},
    platform::Platform,
};

use super::client::{Registry, resolve_platform_digest};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for constructing a [`Registry`] client with optional auth and TLS settings.
pub struct RegistryBuilder {
    pub(super) platform: Platform,
    pub(super) cache: GlobalCache,
    pub(super) auth: oci_client::secrets::RegistryAuth,
    pub(super) insecure_registries: Vec<String>,
    pub(super) extra_ca_certs: Vec<Vec<u8>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RegistryBuilder {
    /// Create a registry builder with anonymous authentication and default TLS settings.
    pub(crate) fn new(platform: Platform, cache: GlobalCache) -> Self {
        Self {
            platform,
            cache,
            auth: oci_client::secrets::RegistryAuth::Anonymous,
            insecure_registries: Vec::new(),
            extra_ca_certs: Vec::new(),
        }
    }

    /// Set authentication credentials for the registry.
    pub fn auth(mut self, auth: RegistryAuth) -> Self {
        self.auth = (&auth).into();
        self
    }

    /// Add registries that should be accessed over plain HTTP instead of HTTPS.
    pub fn add_insecure_registries(mut self, registries: Vec<String>) -> Self {
        self.insecure_registries.extend(registries);
        self
    }

    /// Add PEM-encoded CA root certificates to trust.
    pub fn extra_ca_certs(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.extra_ca_certs = certs;
        self
    }

    /// Build the registry client.
    ///
    /// Returns [`ImageError::InvalidCertificate`] if any PEM data in
    /// `extra_ca_certs` cannot be parsed as valid certificates.
    pub fn build(self) -> ImageResult<Registry> {
        let protocol = if self.insecure_registries.is_empty() {
            ClientProtocol::Https
        } else {
            ClientProtocol::HttpsExcept(self.insecure_registries)
        };

        let mut extra_root_certificates = Vec::new();
        for (i, pem_data) in self.extra_ca_certs.into_iter().enumerate() {
            let certs: Vec<_> = rustls_pemfile::certs(&mut pem_data.as_slice())
                .collect::<Result<_, _>>()
                .map_err(|e| {
                    ImageError::InvalidCertificate(format!("entry {i}: failed to parse: {e}"))
                })?;

            if certs.is_empty() {
                return Err(ImageError::InvalidCertificate(format!(
                    "entry {i}: no certificates found in PEM data"
                )));
            }

            for cert in certs {
                extra_root_certificates.push(Certificate {
                    encoding: CertificateEncoding::Der,
                    data: cert.to_vec(),
                });
            }
        }

        let platform = self.platform.clone();
        let client = Client::new(ClientConfig {
            protocol,
            extra_root_certificates,
            platform_resolver: Some(Box::new(move |manifests| {
                resolve_platform_digest(manifests, &platform)
            })),
            ..Default::default()
        });

        Ok(Registry {
            client,
            auth: self.auth,
            platform: self.platform,
            cache: self.cache,
        })
    }
}
