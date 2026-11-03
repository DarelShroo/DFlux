use rustls::ClientConfig;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("TLS Connection Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Rustls Error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("Hostname mismatch. Expected {expected}, Received {received}")]
    HostnameMismatch { expected: String, received: String },
    #[error("Certificate is not trusted: {subject}")]
    UntrustedCertificate { subject: String },
    #[error("Certificate is expired: {subject}")]
    ExpiredCertificate { subject: String },
    #[error("Certificate chain is incomplete or has an unknown issuer: {subject}")]
    IncompleteChain { subject: String },
    #[error("TLS handshake failed: {0}")]
    HandshakeFailure(String),
    #[error("TCP connection failed before TLS: {0}")]
    TcpConnect(String),
    #[error("TLS handshake timed out")]
    HandshakeTimeout,
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
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

use crate::egress::EgressManager;
use std::sync::LazyLock;
use std::time::Duration;

static TLS_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Arc::new(config)
});

static LOOSE_TLS_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let mut loose_config = ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    loose_config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoVerifier));

    Arc::new(loose_config)
});

pub async fn handshake_and_verify(
    hostname: &str,
    ip: IpAddr,
    port: u16,
    remote: bool,
    egress_mgr: Arc<EgressManager>,
) -> Result<(), TlsError> {
    let server_name = ServerName::try_from(hostname)
        .map_err(|_| TlsError::InvalidDnsName(hostname.to_string()))?
        .to_owned();

    let connector = TlsConnector::from(TLS_CONFIG.clone());

    // Connect TCP
    let stream = crate::outbound::connect_tcp(ip, port, remote, egress_mgr.clone())
        .await
        .map_err(|error| TlsError::TcpConnect(error.to_string()))?;

    let handshake_res = tokio::time::timeout(
        Duration::from_secs(2),
        connector.connect(server_name.clone(), stream),
    )
    .await;

    match handshake_res {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => {
            // Handshake failed. Let's do a loose handshake to inspect the cert.
            let stream2 = match crate::outbound::connect_tcp(ip, port, remote, egress_mgr).await {
                Ok(s) => s,
                Err(error) => return Err(TlsError::TcpConnect(error.to_string())),
            };

            let loose_connector = TlsConnector::from(LOOSE_TLS_CONFIG.clone());

            if let Ok(Ok(tls_stream)) = tokio::time::timeout(
                Duration::from_secs(2),
                loose_connector.connect(server_name, stream2),
            )
            .await
            {
                // Connection succeeded, get peer certificates
                if let Some(certs) = tls_stream.get_ref().1.peer_certificates()
                    && let Some(cert_der) = certs.first()
                    && let Ok((_, x509)) = X509Certificate::from_der(cert_der.as_ref())
                {
                    let subject = x509.subject().to_string();
                    let received = subject
                        .strip_prefix("CN=")
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| subject.clone());
                    if !certificate_matches_hostname(&x509, hostname) {
                        return Err(TlsError::HostnameMismatch {
                            expected: hostname.to_string(),
                            received,
                        });
                    }
                    let rustls_error = e
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<rustls::Error>());
                    return Err(match rustls_error {
                        Some(rustls::Error::InvalidCertificate(
                            rustls::CertificateError::Expired
                            | rustls::CertificateError::ExpiredContext { .. },
                        )) => TlsError::ExpiredCertificate { subject: received },
                        Some(rustls::Error::InvalidCertificate(
                            rustls::CertificateError::UnknownIssuer,
                        )) => TlsError::IncompleteChain { subject: received },
                        Some(rustls::Error::InvalidCertificate(_)) => {
                            TlsError::UntrustedCertificate { subject: received }
                        }
                        _ => TlsError::HandshakeFailure(e.to_string()),
                    });
                }
            }
            Err(TlsError::HandshakeFailure(e.to_string()))
        }
        Err(_) => Err(TlsError::HandshakeTimeout),
    }
}

fn certificate_matches_hostname(cert: &X509Certificate<'_>, hostname: &str) -> bool {
    let expected = hostname.trim_end_matches('.').to_ascii_lowercase();
    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(name) = name {
                names.push(name.to_ascii_lowercase());
            }
        }
    }
    if names.is_empty() {
        names.extend(
            cert.subject()
                .iter_common_name()
                .filter_map(|n| n.as_str().ok())
                .map(str::to_ascii_lowercase),
        );
    }
    names.iter().any(|name| dns_name_matches(name, &expected))
}

fn dns_name_matches(pattern: &str, hostname: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        hostname.strip_suffix(suffix).is_some_and(|prefix| {
            prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
        })
    } else {
        pattern == hostname
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn wildcard_certificate_matches_only_one_label() {
        assert!(dns_name_matches("*.example.com", "www.example.com"));
        assert!(!dns_name_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_name_matches("*.example.com", "example.com"));
        assert!(!dns_name_matches("wolftorrent.com", "core1.netops.test"));
    }
}
