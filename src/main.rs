use cfd::{self, checker::Checker, domain::Domain, helpers::bool_to_str};
use clap::Parser;
use prettytable::{Cell, Row, Table};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;
#[macro_use]
extern crate prettytable;

#[derive(Parser)]
#[command(name = "Cloudflare Detector")]
#[command(author = "Airat G. <hello@galiullin.online>")]
#[command(version = "0.1.0")]
#[command(about = "Checks the domain for Cloudflare presence using 5 criteria: SSL cert issuer, IP address, and three headers in the HTTP response.", long_about = None)]
struct Cli {
    /// A domain, domains divided by newline char or a file with domains.
    target: String,
    /// Outputs a detailed result for each domain based on five checks.
    #[arg(short)]
    detailed: bool,
    /// Outputs only domains without Cloudflare presence.
    #[arg(short)]
    filtered: bool,
    /// The path to the folder where the cfd_report.(txt|csv) file will be stored.
    /// If a file won't be specified, output will be printed to stdout.
    /// If the detailed flag is set, the output will include checking details.
    #[arg(short)]
    output: Option<PathBuf>,
}

// Добавить возможность проверки вектора айпишников для CFIPs

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut target = cli.target;
    let path = Path::new(target.as_str());
    if path.exists() && path.is_file() {
        target = std::fs::read_to_string(path)?;
    }
    let checker = cfd::run(target).await?;
    output(checker, cli.detailed, cli.filtered, cli.output).await?;
    Ok(())
}

async fn output(
    checker: Checker,
    detailed: bool,
    filtered: bool,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let domains;
    if filtered {
        domains = checker.cf_detected_domains().await;
    } else {
        domains = checker.domains;
    }
    if detailed || !detailed && !filtered {
        let mut table = Table::new();
        if detailed {
            build_full_table(&mut table, domains).await?;
        } else {
            build_small_table(&mut table, domains).await?;
        }
        if output.is_some() {
            let path = output
                .unwrap()
                .with_file_name("cfd_report")
                .with_extension("csv");
            let mut file = std::fs::File::create(path)?;
            table.to_csv(&mut file)?;
        } else {
            table.printstd();
        }
    } else {
        if output.is_none() {
            for domain in domains.iter() {
                let domain = domain.lock().await;
                println!("{}", domain.name);
            }
        } else {
            let path = output
                .unwrap()
                .with_file_name("cfd_report")
                .with_extension("txt");
            let mut file = std::fs::File::create(path)?;
            for domain in domains.iter() {
                let domain = domain.lock().await;
                writeln!(file, "{}", domain.name)?;
            }
        }
    }
    Ok(())
}

async fn build_full_table(
    table: &mut Table,
    domains: Vec<Arc<Mutex<Domain>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    table.add_row(row![
        "Domain",
        "Unreachable",
        "CF SSL",
        "CF IP",
        "CF-Ray",
        "CF-Cache-Status",
        "CF-Server"
    ]);
    for domain in domains.iter() {
        let domain = domain.lock().await;
        table.add_row(Row::new(vec![
            Cell::new(domain.name.as_str()),
            Cell::new(bool_to_str(domain.is_unreachable)),
            Cell::new(bool_to_str(domain.has_cf_ssl())),
            Cell::new(bool_to_str(domain.has_cf_ip())),
            Cell::new(bool_to_str(domain.has_cf_ray_header())),
            Cell::new(bool_to_str(domain.has_cf_cache_status_header())),
            Cell::new(bool_to_str(domain.has_cf_server_header())),
        ]));
    }
    Ok(())
}

async fn build_small_table(
    table: &mut Table,
    domains: Vec<Arc<Mutex<Domain>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    table.add_row(row!["Domain", "Status"]);
    for domain in domains.iter() {
        let domain = domain.lock().await;
        table.add_row(Row::new(vec![
            Cell::new(domain.name.as_str()),
            Cell::new(domain.get_status()),
        ]));
    }
    Ok(())
}
