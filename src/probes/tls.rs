use std::net::IpAddr;
use std::sync::Arc;
use rustls::ClientConfig;
use rustls::pki_types::{ServerName, CertificateDer, UnixTime};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;
use thiserror::Error;
use rustls::client::danger::{ServerCertVerifier, HandshakeSignatureValid};
use rustls::DigitallySignedStruct;
use rustls::crypto::aws_lc_rs::default_provider;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("TLS Connection Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Rustls Error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("Hostname mismatch. Expected {expected}, Received {received}")]
    HostnameMismatch {
        expected: String,
        received: String,
    },
    #[error("Invalid DNS name: {0}")]
    InvalidDnsName(String),
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        default_provider().signature_verification_algorithms.supported_schemes()
    }
}

use crate::egress::EgressManager;

pub async fn handshake_and_verify(hostname: &str, ip: IpAddr, port: u16, remote: bool, egress_mgr: Arc<EgressManager>) -> Result<(), TlsError> {
    let server_name = ServerName::try_from(hostname)
        .map_err(|_| TlsError::InvalidDnsName(hostname.to_string()))?
        .to_owned();

    let root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
    );

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    
    // Connect TCP
    let stream = crate::outbound::connect_tcp(ip, port, remote, egress_mgr.clone()).await.map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::Other, "TCP connect failed")
    })?;
    match connector.connect(server_name.clone(), stream).await {
        Ok(_) => {
            // Handshake and verification succeeded
            Ok(())
        }
        Err(e) => {
            // Handshake failed. Let's do a loose handshake to inspect the cert.
            let stream2 = crate::outbound::connect_tcp(ip, port, remote, egress_mgr).await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "TCP connect failed")
            })?;
            
            let mut loose_config = ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            
            loose_config.dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier));

            let loose_connector = TlsConnector::from(Arc::new(loose_config));
            
            if let Ok(tls_stream) = loose_connector.connect(server_name, stream2).await {
                // Connection succeeded, get peer certificates
                if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
                    if let Some(cert_der) = certs.first() {
                        if let Ok((_, x509)) = X509Certificate::from_der(cert_der.as_ref()) {
                            let subject = x509.subject().to_string();
                            // Extract CN from subject, format usually "CN=hostname"
                            let mut received = subject.clone();
                            if subject.starts_with("CN=") {
                                received = subject[3..].to_string();
                            }
                            return Err(TlsError::HostnameMismatch {
                                expected: hostname.to_string(),
                                received,
                            });
                        }
                    }
                }
            }
            // If loose handshake fails or we couldn't parse, just return the original error
            Err(TlsError::Io(e))
        }
    }
}
