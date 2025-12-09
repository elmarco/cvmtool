mod sev;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Specify the provider
    #[arg(short, long)]
    provider: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a report/quote
    Report {
        /// Nonce (hex string). Will be padded with zeros or truncated to 64 bytes.
        #[arg(long, value_parser = parse_hex)]
        nonce: Option<Vec<u8>>,

        /// Output file path. If not specified, the report is printed to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a report
    Verify {
        /// Path to the quote file to verify
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Path to directory containing certificate chain (ark.pem, ask.pem, vcek.pem)
        #[arg(short, long, value_name = "DIR")]
        certs_dir: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let provider = cli.provider;

    match cli.command {
        Commands::Report { nonce, output } => {
            let mut input = [0u8; 64];
            if let Some(n) = nonce {
                let len = n.len().min(64);
                input[..len].copy_from_slice(&n[..len]);
            }

            let quote = if let Some(provider) = provider {
                configfs_tsm::create_quote_with_providers(input, vec![&provider])
            } else {
                configfs_tsm::create_quote(input)
            };
            let quote = quote.map_err(|e| anyhow::anyhow!("Quote generation failed: {:?}", e))?;

            if let Some(path) = output {
                fs::write(&path, &quote)
                    .context(format!("Failed to write report to {}", path.display()))?;
                eprintln!(
                    "Report successfully written to {} in binary format",
                    path.display()
                );
            } else {
                io::stdout()
                    .write_all(&quote)
                    .context("Failed to write report to stdout")?;
            }
        }
        Commands::Verify { path, certs_dir } => {
            let quote_bytes =
                fs::read(&path).context(format!("Failed to read quote file {}", path.display()))?;

            let provider =
                provider.ok_or_else(|| anyhow::anyhow!("The provider must be specified"))?;

            match provider.as_str() {
                "sev_guest" => {
                    let report = sev::parse_report(&quote_bytes)?;

                    println!("{:#?}", report);
                    if let Some(certs_dir) = certs_dir {
                        sev::verify_report(&report, &certs_dir)?;
                        println!("Verification successful!");
                    }
                }
                "tdx_guest" => {
                    let quote = tdx_quote::Quote::from_bytes(&quote_bytes)
                        .map_err(|e| anyhow::anyhow!("Failed to parse TDX quote: {:?}", e))?;
                    println!("{:#?}", quote);
                }
                _ => {
                    return Err(anyhow::anyhow!("Unsupported provider: {}", provider));
                }
            }
        }
    }

    Ok(())
}

fn parse_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}
