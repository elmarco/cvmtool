use assert_cmd::{Command, cargo::cargo_bin_cmd};
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

mod verify {
    use super::*;

    #[test]
    fn sev_with_real_certs() {
        let certs_dir = std::path::Path::new("tests/fixtures/sev-certs");
        let report_path = std::path::Path::new("tests/fixtures/sev.report");

        if !certs_dir.exists() || !report_path.exists() {
            eprintln!(
                "Skipping test: tests/fixtures/sev-certs/ or tests/fixtures/sev.report not found"
            );
            return;
        }

        cvmtool()
            .args(["-p", "sev_guest", "verify"])
            .arg(report_path)
            .args(["--certs-dir"])
            .arg(certs_dir)
            .assert()
            .success()
            .stdout(predicate::str::contains("ARK is self-signed"))
            .stdout(predicate::str::contains("ASK was signed by ARK"))
            .stdout(predicate::str::contains("VCEK was signed by ASK"))
            .stdout(predicate::str::contains("TCB bootloader matches"))
            .stdout(predicate::str::contains("TCB TEE matches"))
            .stdout(predicate::str::contains("TCB SNP matches"))
            .stdout(predicate::str::contains("TCB microcode matches"))
            .stdout(predicate::str::contains(
                "VCEK signed the attestation report",
            ))
            .stdout(predicate::str::contains("Verification successful!"));
    }

    #[test]
    fn sev_with_fake_certs() {
        let certs_dir = std::path::Path::new("tests/fixtures/sev-fake-certs");
        let report_path = std::path::Path::new("tests/fixtures/sev.report");

        if !certs_dir.exists() || !report_path.exists() {
            eprintln!(
                "Skipping test: tests/fixtures/sev-fakecerts/ or tests/fixtures/sev.report not found"
            );
            return;
        }

        cvmtool()
            .args(["-p", "sev_guest", "verify"])
            .arg(report_path)
            .args(["--certs-dir"])
            .arg(certs_dir)
            .assert()
            .failure()
            .stdout(predicate::str::contains("ARK is self-signed"))
            .stdout(predicate::str::contains("ASK was signed by ARK"))
            .stdout(predicate::str::contains("VCEK was signed by ASK"))
            .stderr(predicate::str::contains(
                "Error: VCEK did not sign the attestation report",
            ));
    }

    #[test]
    fn with_unsupported_provider_fails() {
        let temp = TempDir::new().unwrap();
        let report_path = temp.path().join("report.bin");
        fs::write(&report_path, [0u8; 100]).unwrap();

        cvmtool()
            .args(["-p", "unsupported_provider", "verify"])
            .arg(&report_path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("Unsupported provider"));
    }

    #[test]
    fn nonexistent_file_fails() {
        cvmtool()
            .args([
                "-p",
                "sev_guest",
                "verify",
                "/nonexistent/path/to/report.bin",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Failed to read quote file"));
    }

    #[test]
    fn sev_invalid_report_fails() {
        let temp = TempDir::new().unwrap();
        let report_path = temp.path().join("report.bin");
        fs::write(&report_path, [0u8; 100]).unwrap();

        cvmtool()
            .args(["-p", "sev_guest", "verify"])
            .arg(&report_path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("Failed to parse SEV report"));
    }

    #[test]
    fn tdx_invalid_quote_fails() {
        let temp = TempDir::new().unwrap();
        let quote_path = temp.path().join("quote.bin");
        fs::write(&quote_path, [0u8; 100]).unwrap();

        cvmtool()
            .args(["-p", "tdx_guest", "verify"])
            .arg(&quote_path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("Failed to parse TDX quote"));
    }

    #[test]
    fn sev_missing_certs_fails() {
        let report_path = std::path::Path::new("tests/fixtures/sev.report");
        if !report_path.exists() {
            eprintln!("Skipping test: tests/fixtures/sev.report not found");
            return;
        }

        let temp = TempDir::new().unwrap();
        let certs_dir = temp.path().join("certs");
        fs::create_dir(&certs_dir).unwrap();

        cvmtool()
            .args(["-p", "sev_guest", "verify"])
            .arg(report_path)
            .args(["--certs-dir"])
            .arg(&certs_dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("ark certificate not found"));
    }
}

fn cvmtool() -> Command {
    cargo_bin_cmd!("cvmtool")
}
