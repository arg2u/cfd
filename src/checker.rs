//! This structure joins domains and cf_ips together to execute checking tasks concurrently.

use crate::cf_ips::CFIPs;
use crate::domain::Domain;
use std::{error::Error, sync::Arc};
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct Checker {
    pub domains: Vec<Arc<Mutex<Domain>>>,
    pub cf_ips: Arc<CFIPs>,
}

impl Checker {
    /// Build a new checker instance.
    /// The function takes one or several domains separated by newline characters as input
    /// #Example:
    /// ```
    /// use cfd::checker::Checker;
    /// #[tokio::main]
    /// async fn main(){
    ///     let solo_target = "example.com";
    ///     let multi_target = "example.com\nexample2.com\nexample3.com";
    ///     let solo_checker = Checker::build(solo_target.to_string()).await;
    ///     let multi_checker = Checker::build(solo_target.to_string()).await;
    ///     assert!(solo_checker.is_ok());
    ///     assert!(multi_checker.is_ok());
    /// }
    /// ```
    pub async fn build(target: String) -> Result<Self, Box<dyn Error>> {
        let target = target.split("\n").collect::<Vec<&str>>();
        let mut domains = vec![];
        target.iter().for_each(|domain| {
            if let Ok(domain) = Domain::build(domain.to_string()) {
                domains.push(Arc::new(Mutex::new(domain)));
            }
        });
        let cf_ips = CFIPs::load().await?;
        Ok(Self {
            domains,
            cf_ips: Arc::new(cf_ips),
        })
    }
}

impl Checker {
    /// Starts a check to determine if domains are behind CF.
    /// #Example:
    /// ```
    /// use cfd::checker::Checker;
    /// #[tokio::main]
    /// async fn main(){
    ///    let target = "cloudflare.com";
    ///    let mut checker = Checker::build(target.to_string()).await.unwrap();
    ///    checker.check().await.unwrap();
    ///    assert_eq!(checker.cf_detected_domains().await.len() > 0, true);
    /// }
    /// ```
    pub async fn check(&mut self) -> Result<(), Box<dyn Error>> {
        let mut handles = vec![];
        for domain in self.domains.iter_mut() {
            let cf_ips = self.cf_ips.clone();
            let domain = domain.clone();
            let handle = tokio::spawn(async move {
                domain.lock().await.verify_domain(cf_ips).await.unwrap();
            });
            handles.push(handle);
        }
        for handle in handles {
            handle.await?;
        }
        Ok(())
    }
}

impl Checker {
    /// Returns a vector of domains that are behind CF.
    /// #Example:
    /// ```
    /// use cfd::checker::Checker;
    /// #[tokio::main]
    /// async fn main(){
    ///    let target = "example.com\ncloudflare.com";
    ///    let mut checker = Checker::build(target.to_string()).await.unwrap();
    ///    checker.check().await.unwrap();
    ///    assert_eq!(checker.cf_detected_domains().await.len() == 1, true);
    /// }
    /// ```
    pub async fn cf_detected_domains(&self) -> Vec<Arc<Mutex<Domain>>> {
        let mut v = vec![];
        let iter = self.domains.iter();
        for domain in iter {
            let domain = domain.clone();
            if domain.lock().await.check_result != 0 {
                v.push(domain.clone());
            }
        }
        v
    }
}
