//! Domain struct and methods to work with it.

use crate::cf_ips::CFIPs;
use rustls::{Certificate, OwnedTrustAnchor, RootCertStore};
use std::{error::Error, sync::Arc};
use std::{io::Write, net::TcpStream};

/// A struct to represent bits of a domain checking result.
pub mod check_result {
    pub const EMPTY: u8 = 0b00000;
    pub const CF_IP: u8 = 0b00001;
    pub const CF_RAY_HEADER: u8 = 0b00010;
    pub const CF_CACHE_STATUS_HEADER: u8 = 0b00100;
    pub const CF_SERVER: u8 = 0b01000;
    pub const CF_SSL: u8 = 0b10000;
}

#[derive(Debug, Clone)]
pub struct Domain {
    /// A domain name.
    pub name: String,
    /// A bit mask to represent the result of the check.
    pub check_result: u8,
    /// If the domain is unreachable, it will be set to true.
    pub is_unreachable: bool,
}

impl Domain {
    /// Builds a new domain instance.
    /// The function takes a domain name as input.
    /// #Example:
    /// ```
    /// use cfd::domain::Domain;
    /// #[tokio::main]
    /// async fn main(){
    ///     let target = "example.com";
    ///     let fail_target = "-example.com!";
    ///     let domain = Domain::build(target.to_string());
    ///     assert!(domain.is_ok());
    ///     let fail_domain = Domain::build(fail_target.to_string());
    ///     assert!(fail_domain.is_err());
    /// }
    /// ```
    pub fn build(name: String) -> Result<Self, String> {
        if Self::is_valid(&name) {
            return Ok(Self {
                name: Domain::clear_name_from_proto(&name),
                check_result: check_result::EMPTY,
                is_unreachable: false,
            });
        } else {
            return Err(format!("Invalid domain name: {}", name));
        };
    }
}

impl Domain {
    /// Checks domain's basic validity.
    /// #Example:
    /// ```
    /// use cfd::domain::Domain;
    /// #[tokio::main]
    /// async fn main(){
    ///     let target = "example.com";
    ///     let fail_target = "-example.com!";
    ///     let is_valid = Domain::is_valid(&target.to_string());
    ///     assert_eq!(is_valid, true);
    ///     let is_not_valid = Domain::is_valid(&fail_target.to_string());
    ///     assert_ne!(is_not_valid, true);
    /// }
    /// ```
    pub fn is_valid(domain: &String) -> bool {
        let domain = Domain::clear_name_from_proto(domain);
        if domain.is_empty() {
            return false;
        }
        if domain.len() > 253 {
            return false;
        }
        let labels = domain.split('.').collect::<Vec<_>>();
        if labels.len() < 2 {
            return false;
        }
        for label in labels {
            if label.len() > 63 {
                return false;
            }
            if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
                return false;
            }
            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }
        }
        true
    }
    /// Clears a domain name from http(s):// prefix.
    ///     /// #Example:
    /// ```
    /// use cfd::domain::Domain;
    /// #[tokio::main]
    /// async fn main(){
    ///     let target = vec!["http://example.com","https://example.com"];
    ///     for domain in target {
    ///        let res = Domain::clear_name_from_proto(&domain.to_string());
    ///       assert_eq!(res, "example.com".to_string());
    ///     }
    /// }
    /// ```
    pub fn clear_name_from_proto(domain: &String) -> String {
        let domain = domain.trim();
        let domain_chunks = domain.split("://").collect::<Vec<&str>>();
        if domain_chunks.len() > 1 {
            if domain_chunks[0] == "http" || domain_chunks[0] == "https" {
                domain_chunks[1].to_string()
            } else {
                panic!("Invalid proto: {}", domain_chunks[0]);
            }
        } else {
            domain.to_string()
        }
    }
}

impl Domain {
    /// Checks the domain for five signs to see if it is behind CF.
    /// The function takes a CFIPs (CloudFlare IPs) instance as input.
    /// #Example:
    /// ```
    /// use cfd::{domain::Domain, cf_ips::CFIPs};
    /// use std::sync::Arc;
    /// #[tokio::main]
    /// async fn main(){
    ///     let target = "http://cloudflare.com".to_string();
    ///     let cf_ips = Arc::new(CFIPs::load().await.unwrap());
    ///     let mut domain = Domain::build(target).unwrap();
    ///     domain.verify_domain(cf_ips).await.unwrap();
    ///     assert_eq!(domain.check_result, 0b11111);
    /// }
    /// ```
    pub async fn verify_domain(&mut self, cf_ips: Arc<CFIPs>) -> Result<(), Box<dyn Error>> {
        let mut result = check_result::EMPTY;
        if let Ok(resp) = reqwest::get("http://".to_string() + &self.name).await {
            let ip = resp.remote_addr();
            if ip.is_some() && cf_ips.check_ip_v4(ip.unwrap().ip().to_string().as_str()) {
                result |= check_result::CF_IP;
            }
            if resp.headers().get("cf-ray").is_some() {
                result |= check_result::CF_RAY_HEADER;
            }
            if resp.headers().get("cf-cache-status").is_some() {
                result |= check_result::CF_CACHE_STATUS_HEADER;
            }
            if resp
                .headers()
                .get("server")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("cloudflare")
            {
                result |= check_result::CF_SERVER;
            }
            if self.get_certificate_info().await.is_ok() {
                result |= check_result::CF_SSL;
            }
        } else {
            self.is_unreachable = true
        }
        self.check_result = result;
        Ok(())
    }
}

impl Domain {
    /// Gets domain's certificate info and checks if its issuer is CF.
    /// #Example:
    /// ```
    /// use cfd::{domain::Domain, cf_ips::CFIPs};
    /// use std::sync::Arc;
    /// #[tokio::main]
    /// async fn main(){
    ///     let target = "http://cloudflare.com".to_string();
    ///     let cf_ips = Arc::new(CFIPs::load().await.unwrap());
    ///     let mut domain = Domain::build(target).unwrap();
    ///     let res = domain.get_certificate_info().await.unwrap();
    ///     assert_eq!(res, true);
    /// }
    /// ```
    pub async fn get_certificate_info(&self) -> Result<bool, Box<dyn Error>> {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let domain = &Domain::clear_name_from_proto(&self.name)[..];
        let server_name = domain.try_into().unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
        let mut sock = TcpStream::connect((domain, 443))?;
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(
            concat!(
                "GET / HTTP/1.1\r\n",
                "Host: google.com\r\n",
                "Connection: close\r\n",
                "Accept-Encoding: identity\r\n",
                "\r\n"
            )
            .as_bytes(),
        )?;
        let certs = tls.conn.peer_certificates().unwrap();
        for cert in certs {
            if Domain::get_cert_issuer(cert)
                .to_lowercase()
                .contains("cloudflare")
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn get_cert_issuer(cert: &Certificate) -> String {
        let cert = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
        cert.1.issuer.to_string()
    }
}

impl Domain {
    /// Checks if domain has CF's SSL.
    /// #Example:
    /// ```
    /// use cfd::{domain::Domain, cf_ips::CFIPs};
    /// use std::sync::Arc;
    /// #[tokio::main]
    /// async fn main(){
    ///     let target = "http://cloudflare.com".to_string();
    ///     let cf_ips = Arc::new(CFIPs::load().await.unwrap());
    ///     let mut domain = Domain::build(target).unwrap();
    ///     domain.verify_domain(cf_ips).await.unwrap();
    ///     assert_eq!(domain.has_cf_ssl(), true);
    /// }
    /// ```
    pub fn has_cf_ssl(&self) -> bool {
        self.check_result & check_result::CF_SSL != 0
    }
    /// Checks if domain has CF's IP.
    /// #Example:
    /// ```
    /// use cfd::{domain::Domain, cf_ips::CFIPs};
    /// use std::sync::Arc;
    /// #[tokio::main]
    /// async fn main(){
    ///     let target = "http://cloudflare.com".to_string();
    ///     let cf_ips = Arc::new(CFIPs::load().await.unwrap());
    ///     let mut domain = Domain::build(target).unwrap();
    ///     domain.verify_domain(cf_ips).await.unwrap();
    ///     assert_eq!(domain.has_cf_ip(), true);
    /// }
    /// ```
    pub fn has_cf_ip(&self) -> bool {
        self.check_result & check_result::CF_IP != 0
    }
    /// Checks if domain has CF-Ray header.
    /// #Example:
    /// ```
    /// use cfd::{domain::Domain, cf_ips::CFIPs};
    /// use std::sync::Arc;
    /// #[tokio::main]
    /// async fn main(){
    ///     let target = "http://cloudflare.com".to_string();
    ///     let cf_ips = Arc::new(CFIPs::load().await.unwrap());
    ///     let mut domain = Domain::build(target).unwrap();
    ///     domain.verify_domain(cf_ips).await.unwrap();
    ///     assert_eq!(domain.has_cf_ray_header(), true);
    /// }
    /// ```
    pub fn has_cf_ray_header(&self) -> bool {
        self.check_result & check_result::CF_RAY_HEADER != 0
    }
    /// Checks if domain has CF-Cache-Status header.
    /// #Example:
    /// ```
    /// use cfd::{domain::Domain, cf_ips::CFIPs};
    /// use std::sync::Arc;
    /// #[tokio::main]
    /// async fn main(){
    ///     let target = "http://cloudflare.com".to_string();
    ///     let cf_ips = Arc::new(CFIPs::load().await.unwrap());
    ///     let mut domain = Domain::build(target).unwrap();
    ///     domain.verify_domain(cf_ips).await.unwrap();
    ///     assert_eq!(domain.has_cf_cache_status_header(), true);
    /// }
    /// ```
    pub fn has_cf_cache_status_header(&self) -> bool {
        self.check_result & check_result::CF_CACHE_STATUS_HEADER != 0
    }
    /// Checks if domain has cloudflare server header.
    /// #Example:
    /// ```
    /// use cfd::{domain::Domain, cf_ips::CFIPs};
    /// use std::sync::Arc;
    /// #[tokio::main]
    /// async fn main(){
    ///     let target = "http://cloudflare.com".to_string();
    ///     let cf_ips = Arc::new(CFIPs::load().await.unwrap());
    ///     let mut domain = Domain::build(target).unwrap();
    ///     domain.verify_domain(cf_ips).await.unwrap();
    ///     assert_eq!(domain.has_cf_server_header(), true);
    /// }
    /// ```
    pub fn has_cf_server_header(&self) -> bool {
        self.check_result & check_result::CF_SERVER != 0
    }
}

impl Domain {
    /// Returns domain status.
    /// #Example:
    /// ```
    /// use cfd::{domain::Domain, cf_ips::CFIPs};
    /// use std::sync::Arc;
    /// #[tokio::main]
    /// async fn main(){
    ///     let target = "http://cloudflare.com".to_string();
    ///     let cf_ips = Arc::new(CFIPs::load().await.unwrap());
    ///     let mut domain = Domain::build(target).unwrap();
    ///     domain.verify_domain(cf_ips).await.unwrap();
    ///     assert_eq!(domain.get_status(), "CF detected");
    /// }
    /// ```
    pub fn get_status(&self) -> &str {
        let status;
        if self.is_unreachable {
            status = "Unreachable";
        } else if self.check_result != 0 {
            status = "CF detected";
        } else {
            status = "CF not detected";
        }
        status
    }
}
