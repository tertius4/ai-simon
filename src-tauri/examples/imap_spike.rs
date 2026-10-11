use std::{env, fs::File, io::BufReader, sync::Arc};

use futures::TryStreamExt;
use mail_parser::MessageParser;
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use tokio_rustls::TlsConnector;

/// Aanvaar net die sertifikaat wat ons vooraf gelaai het.
#[derive(Debug)]
struct PinnedCertVerifier {
    pinned: CertificateDer<'static>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedCertVerifier {
    fn new(pinned: CertificateDer<'static>, provider: &CryptoProvider) -> Self {
        Self { pinned, algs: provider.signature_verification_algorithms }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if end_entity.as_ref() == self.pinned.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("server certificate does not match pinned certificate".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn build_config(pem_path: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(pem_path)?);
    let pinned = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or("geen sertifikaat in die PEM-lêer")??;
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier::new(pinned, &provider)))
        .with_no_client_auth();
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let user = env::var("BRIDGE_USER")?;
    let pass = env::var("BRIDGE_PASS")?;
    let cert_path = env::var("BRIDGE_CERT")?;

    let tcp = TcpStream::connect("127.0.0.1:1143").await?;
    let mut client = async_imap::Client::new(tcp);
    let _greeting = client.read_response().await;
    client.run_command_and_check_ok("STARTTLS", None).await?;
    let tcp = client.into_inner();

    let connector = TlsConnector::from(Arc::new(build_config(&cert_path)?));
    let tls = connector
        .connect(ServerName::try_from("127.0.0.1")?, tcp)
        .await?;

    let client = async_imap::Client::new(tls);
    let mut session = client.login(user, pass).await.map_err(|(e, _)| e)?;

    let folders: Vec<_> = session.list(Some(""), Some("*")).await?.try_collect().await?;
    for f in &folders {
        println!("vouer: {}", f.name());
    }

    let inbox = session.select("INBOX").await?;
    println!("INBOX: exists={} uid_validity={:?}", inbox.exists, inbox.uid_validity);

    if inbox.exists > 0 {
        let start = inbox.exists.saturating_sub(4).max(1);
        let range = format!("{}:{}", start, inbox.exists);
        let msgs: Vec<_> = session
            .fetch(range, "(UID BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])")
            .await?
            .try_collect()
            .await?;
        for m in &msgs {
            let Some(hdr) = m.header() else { continue };
            let Some(msg) = MessageParser::default().parse(hdr) else { continue };
            println!(
                "uid={:?} | {} | {} | {}",
                m.uid,
                msg.date().map(|d| d.to_rfc3339()).unwrap_or_default(),
                msg.from().and_then(|a| a.first()).and_then(|a| a.address()).unwrap_or("?"),
                msg.subject().unwrap_or("(geen onderwerp)"),
            );
        }
    }

    session.logout().await?;
    Ok(())
}