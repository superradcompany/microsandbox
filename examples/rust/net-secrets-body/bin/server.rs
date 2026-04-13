//! Self-signed HTTPS mock server that logs received request bodies.

use axum::{Router, extract::Json, routing::post};
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// A running HTTPS server handle. Holds the path to the CA cert PEM file
/// so the TLS proxy can trust it.
pub struct ServerHandle {
    pub ca_cert_path: PathBuf,
}

/// Spawn an HTTPS server in the background that echoes POST bodies.
/// Returns a handle containing the path to the server's CA cert PEM.
pub async fn spawn(hostname: &str, port: u16) -> std::io::Result<ServerHandle> {
    let (tls_config, cert_pem) = build_tls_config(hostname);
    let acceptor = TlsAcceptor::from(tls_config);
    let app = Router::new().route("/echo", post(handle_echo));
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;

    // Write the self-signed cert to a temp file so the TLS proxy can trust it.
    let ca_cert_path = std::env::temp_dir().join("msb-net-secrets-body-ca.pem");
    std::fs::write(&ca_cert_path, &cert_pem)?;

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(tls);
                let service = hyper::service::service_fn(move |req| {
                    let mut app = app.clone();
                    async move { tower::Service::call(&mut app, req).await }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, service)
                .await;
            });
        }
    });

    Ok(ServerHandle { ca_cert_path })
}

async fn handle_echo(Json(body): Json<serde_json::Value>) -> String {
    let key = body.get("key").and_then(|v| v.as_str()).unwrap_or("?");
    println!("[server] Received key = {key}");
    format!("{{\"received_key\": \"{key}\"}}")
}

fn build_tls_config(hostname: &str) -> (Arc<ServerConfig>, String) {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let cert =
        generate_simple_self_signed(vec![hostname.to_string()]).expect("cert generation failed");
    let cert_pem = cert.cert.pem();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("TLS config failed"),
    );

    (config, cert_pem)
}
