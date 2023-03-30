use std::time::Instant;

use checker::Checker;

pub mod cf_ips;
pub mod checker;
pub mod domain;
pub mod helpers;

/// Runs the checker.
/// #Example:
/// ```
/// use cfd::run;
/// #[tokio::main]
/// async fn main(){
///   let target = "example.com\ncloudflare.com";
///   let checker = run(target.to_string()).await.unwrap();
///   assert_eq!(checker.cf_detected_domains().await.len() == 1, true);
/// }
/// ```
pub async fn run(target: String) -> Result<Checker, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut checker = checker::Checker::build(String::from(target.as_str())).await?;
    checker.check().await?;
    let end = Instant::now();
    let duration = end - start;
    println!(
        "Finished in {:.2?} for {} domain(s)",
        duration,
        checker.domains.len()
    );
    Ok(checker)
}
