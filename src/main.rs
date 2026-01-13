use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

mod pck;
mod sev;
mod tdx;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a report/quote
    Report {
        /// Path to the report file to create ('-' for stdout)
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// The report format ('sev', 'tdx')
        #[arg(short, long)]
        format: Option<String>,

        /// Report data (hex string). Will be padded with zeros or truncated to 64 bytes.
        #[arg(long)]
        report_data: Option<String>,
    },
    /// Verify a report
    Verify {
        /// Path to the report file to verify ('-' for stdin)
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// The report format ('sev', 'tdx')
        #[arg(short, long)]
        format: Option<String>,

        /// Path to directory containing certificate chain
        #[arg(short, long, value_name = "DIR")]
        certs_dir: Option<PathBuf>,

        /// Expected report data (hex string). Will be padded with zeros or truncated to 64 bytes.
        #[arg(long)]
        expected_report_data: Option<String>,

        /// Expected launch measurement (hex string, 48 bytes for SEV/TDX MRTD)
        #[arg(long)]
        expected_measurement: Option<String>,

        /// Expected host data (hex string, 32 bytes, SEV only)
        #[arg(long)]
        expected_host_data: Option<String>,

        /// Expected ID key digest (hex string, 48 bytes, SEV only)
        #[arg(long)]
        expected_id_key_digest: Option<String>,

        /// Expected RTMR0 value (hex string, 48 bytes, TDX only)
        #[arg(long)]
        expected_rtmr0: Option<String>,

        /// Expected RTMR1 value (hex string, 48 bytes, TDX only)
        #[arg(long)]
        expected_rtmr1: Option<String>,

        /// Expected RTMR2 value (hex string, 48 bytes, TDX only)
        #[arg(long)]
        expected_rtmr2: Option<String>,

        /// Expected RTMR3 value (hex string, 48 bytes, TDX only)
        #[arg(long)]
        expected_rtmr3: Option<String>,

        /// Require debug mode to be disabled
        #[arg(long)]
        require_no_debug: bool,

        /// Require migration to be disabled (SEV only)
        #[arg(long)]
        require_no_migration: bool,

        /// Minimum TCB versions as bootloader:tee:snp:microcode (e.g., "3:0:8:209", SEV only)
        #[arg(long, value_parser = parse_min_tcb)]
        min_tcb: Option<(u8, u8, u8, u8)>,
    },
    /// Fetch PCK certificate from Intel PCS (for TDX hosts)
    FetchPck {
        /// Output directory for certificates
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
}

/// Options for attestation verification beyond cryptographic checks
#[derive(Debug, Default, Clone)]
pub struct VerifyOptions {
    /// Expected report data (hex string). Will be padded with zeros or truncated to 64 bytes.
    pub expected_report_data: Option<String>,
    /// Expected launch measurement (hex string, SEV: 48 bytes, TDX MRTD: 48 bytes)
    pub expected_measurement: Option<String>,
    /// Expected host data (hex string, SEV only, 32 bytes)
    pub expected_host_data: Option<String>,
    /// Expected ID key digest (hex string, SEV only, 48 bytes)
    pub expected_id_key_digest: Option<String>,
    /// Expected RTMR values (hex string, TDX only, 48 bytes each)
    pub expected_rtmr0: Option<String>,
    pub expected_rtmr1: Option<String>,
    pub expected_rtmr2: Option<String>,
    pub expected_rtmr3: Option<String>,
    /// Require debug mode to be disabled
    pub require_no_debug: bool,
    /// Require migration to be disabled (SEV only)
    pub require_no_migration: bool,
    /// Minimum TCB versions (SEV only): (bootloader, tee, snp, microcode)
    pub min_tcb: Option<(u8, u8, u8, u8)>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Report {
            path,
            format,
            report_data,
        } => {
            let mut input = [0u8; 64];
            if let Some(n) = report_data {
                let n = hex::decode(&n).context("Invalid hex string for report data")?;
                let len = n.len().min(64);
                input[..len].copy_from_slice(&n[..len]);
            }

            let quote = if let Some(format) = format {
                match format.as_str() {
                    "sev" => configfs_tsm::create_quote_with_providers(input, vec![&"sev-guest"]),
                    "tdx" => configfs_tsm::create_quote_with_providers(input, vec![&"tdx-guest"]),
                    _ => Err(anyhow::anyhow!("Unsupported report format: {}", format))?,
                }
            } else {
                configfs_tsm::create_quote(input)
            };
            let quote = quote.map_err(|e| anyhow::anyhow!("Quote generation failed: {:?}", e))?;

            if path.to_str() == Some("-") {
                io::stdout()
                    .write_all(&quote)
                    .context("Failed to write report to stdout")?;
            } else {
                fs::write(&path, &quote)
                    .context(format!("Failed to write report to {}", path.display()))?;
                eprintln!(
                    "Report successfully written to {} in binary format",
                    path.display()
                );
            }
        }
        Commands::Verify {
            path,
            format,
            certs_dir,
            expected_report_data,
            expected_measurement,
            expected_host_data,
            expected_id_key_digest,
            expected_rtmr0,
            expected_rtmr1,
            expected_rtmr2,
            expected_rtmr3,
            require_no_debug,
            require_no_migration,
            min_tcb,
        } => {
            let report_bytes = if path.to_str() == Some("-") {
                let mut buf = Vec::new();
                io::stdin()
                    .read_to_end(&mut buf)
                    .context("Failed to write report from stdin")?;
                buf
            } else {
                fs::read(&path).context(format!("Failed to read report file {}", path.display()))?
            };

            let format = format.ok_or_else(|| anyhow::anyhow!("The format must be specified"))?;

            let opts = VerifyOptions {
                expected_report_data,
                expected_measurement,
                expected_host_data,
                expected_id_key_digest,
                expected_rtmr0,
                expected_rtmr1,
                expected_rtmr2,
                expected_rtmr3,
                require_no_debug,
                require_no_migration,
                min_tcb,
            };

            match format.as_str() {
                "sev" => {
                    let report = sev::parse_report(&report_bytes)?;
                    println!("{:#?}", report);
                    if let Some(certs_dir) = certs_dir {
                        sev::verify_report(&report, &certs_dir, &opts)?;
                        println!("Verification successful!");
                    }
                }
                "tdx" => {
                    let quote = tdx::parse_quote(&report_bytes)?;
                    println!("{:#?}", quote);
                    tdx::verify_quote(&quote, certs_dir.as_deref(), &opts)?;
                    println!("Verification successful!");
                }
                _ => {
                    return Err(anyhow::anyhow!("Unsupported format: {}", format));
                }
            }
        }
        Commands::FetchPck { output } => {
            eprintln!("Retrieving platform information...");
            let platform_info = pck::get_platform_info()?;
            eprintln!("Platform info retrieved:");
            eprintln!(
                "  PPID: {}...",
                &platform_info.encrypted_ppid[..32.min(platform_info.encrypted_ppid.len())]
            );
            eprintln!("  PCE ID: {}", platform_info.pce_id);
            eprintln!("  CPU SVN: {}", platform_info.cpu_svn);
            eprintln!("  PCE SVN: {}", platform_info.pce_svn);
            eprintln!("  QE ID: {}", platform_info.qe_id);

            eprintln!("\nFetching PCK certificate from Intel PCS...");
            let response = pck::fetch_pck_certificate(&platform_info)?;
            eprintln!("Certificate retrieved:");
            eprintln!("  FMSPC: {}", response.fmspc);
            eprintln!("  TCBm: {}", response.tcbm);
            eprintln!("  CA Type: {}", response.ca_type);

            eprintln!("\nSaving certificates...");
            pck::save_certificates(&response, &output)?;
            eprintln!("\nDone!");
        }
    }

    Ok(())
}

fn parse_min_tcb(s: &str) -> Result<(u8, u8, u8, u8), String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 4 {
        return Err("Expected format: bootloader:tee:snp:microcode (e.g., 3:0:8:209)".to_string());
    }
    let bootloader = parts[0]
        .parse::<u8>()
        .map_err(|_| "Invalid bootloader version")?;
    let tee = parts[1].parse::<u8>().map_err(|_| "Invalid tee version")?;
    let snp = parts[2].parse::<u8>().map_err(|_| "Invalid snp version")?;
    let microcode = parts[3]
        .parse::<u8>()
        .map_err(|_| "Invalid microcode version")?;
    Ok((bootloader, tee, snp, microcode))
}
