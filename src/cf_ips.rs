//! Cloudflare IP ranges provider.
//! It's main function is to load and provide a list of Cloudflare IP ranges.

use crate::helpers::{split_to_string_vec, string_to_binary};

#[derive(Debug)]
pub struct CFIPs {
    pub ipsv4: Vec<String>,
    pub ipsv6: Vec<String>,
}

impl CFIPs {
    pub async fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let ipsv4 = Self::load_ips("https://www.cloudflare.com/ips-v4").await?;
        let ipsv6 = Self::load_ips("https://www.cloudflare.com/ips-v6").await?;
        Ok(Self { ipsv4, ipsv6 })
    }

    async fn load_ips(url: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        Ok(split_to_string_vec(
            reqwest::get(url).await?.text().await?,
            "\n",
        ))
    }
}

impl CFIPs {
    /// Checks if an IPv4 is CF's.
    /// #Example:
    /// ```
    /// use cfd::cf_ips::CFIPs;
    /// #[tokio::main]
    /// async fn main(){
    ///     let cf_ips = CFIPs::load().await.unwrap();
    ///     assert!(cf_ips.check_ip_v4("131.0.72.1"));
    /// }
    /// ```
    ///
    pub fn check_ip_v4(&self, ip: &str) -> bool {
        self.ipsv4
            .iter()
            .any(|cidr| CFIPs::check_ip_in_cidr(ip, cidr))
    }

    /// Checks if an IPv4 address is in a given CIDR range
    /// #Example:
    /// ```
    /// use cfd::cf_ips::CFIPs;
    /// assert!(CFIPs::check_ip_in_cidr("131.0.72.1", "131.0.72.0/22"));
    /// ```
    ///
    pub fn check_ip_in_cidr(ip: &str, cidr_range: &str) -> bool {
        // parse ip and cidr range
        let ip_parts: Vec<&str> = ip.split(".").collect();
        let cidr_parts: Vec<&str> = cidr_range.split("/").collect();
        let mask_size: u8 = cidr_parts[1].parse().unwrap_or(0);

        // check if ip and cidr have the same network class
        if ip_parts.len() != 4 || cidr_parts[0].split(".").collect::<Vec<&str>>().len() != 4 {
            return false;
        }

        // convert ip and cidr to binary strings
        let ip_bin = ip_parts
            .iter()
            .map(|x| string_to_binary(x))
            .collect::<String>();
        let cidr_bin = cidr_parts[0]
            .split(".")
            .map(|x| string_to_binary(x))
            .collect::<String>();

        // check if the first n bits of the ip match the first n bits of the cidr range
        if ip_bin[0..mask_size as usize] == cidr_bin[0..mask_size as usize] {
            return true;
        }
        false
    }
}
