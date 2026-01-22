// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result, anyhow};
use tss_esapi::{
    abstraction::nv,
    handles::NvIndexTpmHandle,
    interface_types::{resource_handles::NvAuth, session_handles::AuthSession},
    tcti_ldr::{DeviceConfig, TctiNameConf},
};

use super::cpuid::{IsolationType, get_isolation_type};
use super::runtime_claims::RuntimeClaims;

const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;

// https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design#attestation-report-format
const SNP_REPORT_SIZE: usize = 1184;
const TDX_REPORT_SIZE: usize = 1024;

const HCL_HEADER_SIZE: usize = 32;
const HCL_SIGNATURE: u32 = 0x414c4348; // "HCLA"
const HCL_HEADER_VERSION: u32 = 2;
const HCL_REQUEST_TYPE_ATTESTATION: u32 = 2;

const RUNTIME_DATA_HEADER_SIZE: usize = 20;
const RUNTIME_DATA_VERSION: u32 = 1;
const RUNTIME_DATA_REPORT_TYPE_SNP: u32 = 2;
const RUNTIME_DATA_REPORT_TYPE_TDX: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    Sha256,
    Sha384,
    Sha512,
}

impl HashType {
    fn from_u32(value: u32) -> Result<Self> {
        match value {
            1 => Ok(HashType::Sha256),
            2 => Ok(HashType::Sha384),
            3 => Ok(HashType::Sha512),
            _ => Err(anyhow!("Unknown hash type: {}", value)),
        }
    }
}

#[derive(Debug)]
#[allow(unused)]
pub struct HclHeader {
    pub signature: u32,
    pub version: u32,
    pub report_size: u32,
    pub request_type: u32,
    pub status: u32,
}

impl HclHeader {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HCL_HEADER_SIZE {
            return Err(anyhow!(
                "HCL header too small: expected {} bytes, got {}",
                HCL_HEADER_SIZE,
                data.len()
            ));
        }

        let signature = u32::from_le_bytes(data[0..4].try_into()?);
        let version = u32::from_le_bytes(data[4..8].try_into()?);
        let report_size = u32::from_le_bytes(data[8..12].try_into()?);
        let request_type = u32::from_le_bytes(data[12..16].try_into()?);
        let status = u32::from_le_bytes(data[16..20].try_into()?);

        if signature != HCL_SIGNATURE {
            return Err(anyhow!(
                "Invalid HCL signature: expected 0x{:08x}, got 0x{:08x}",
                HCL_SIGNATURE,
                signature
            ));
        }

        if version != HCL_HEADER_VERSION {
            eprintln!(
                "Unsupported HCL version: expected {}, got {}",
                HCL_HEADER_VERSION, version
            );
        }

        if request_type != HCL_REQUEST_TYPE_ATTESTATION {
            return Err(anyhow!(
                "Invalid request type: expected {}, got {}",
                HCL_REQUEST_TYPE_ATTESTATION,
                request_type
            ));
        }

        Ok(Self {
            signature,
            version,
            report_size,
            request_type,
            status,
        })
    }
}

#[derive(Debug)]
#[allow(unused)]
pub struct RuntimeData {
    pub data_size: u32,
    pub version: u32,
    pub report_type: u32,
    pub hash_type: HashType,
    pub claims_raw: Vec<u8>,
    pub claims: RuntimeClaims,
}

impl RuntimeData {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < RUNTIME_DATA_HEADER_SIZE {
            return Err(anyhow!(
                "Runtime data too small: expected at least {} bytes, got {}",
                RUNTIME_DATA_HEADER_SIZE,
                data.len()
            ));
        }

        let data_size = u32::from_le_bytes(data[0..4].try_into()?);
        let version = u32::from_le_bytes(data[4..8].try_into()?);
        let report_type = u32::from_le_bytes(data[8..12].try_into()?);
        let hash_type_raw = u32::from_le_bytes(data[12..16].try_into()?);
        let claim_size = u32::from_le_bytes(data[16..20].try_into()?);

        if version != RUNTIME_DATA_VERSION {
            return Err(anyhow!(
                "Unsupported runtime data version: expected {}, got {}",
                RUNTIME_DATA_VERSION,
                version
            ));
        }

        let hash_type = HashType::from_u32(hash_type_raw)?;

        let claims_end = RUNTIME_DATA_HEADER_SIZE + claim_size as usize;
        if data.len() < claims_end {
            return Err(anyhow!(
                "Runtime data truncated: expected {} bytes for claims, got {}",
                claim_size,
                data.len() - RUNTIME_DATA_HEADER_SIZE
            ));
        }

        let claims_raw = data[RUNTIME_DATA_HEADER_SIZE..claims_end].to_vec();
        let claims: RuntimeClaims =
            serde_json::from_slice(&claims_raw).context("Failed to parse runtime claims JSON")?;

        Ok(Self {
            data_size,
            version,
            report_type,
            hash_type,
            claims_raw,
            claims,
        })
    }
}

#[derive(Debug)]
#[allow(unused)]
pub struct Report {
    pub header: HclHeader,
    pub isolation_type: IsolationType,
    pub hw_report: Vec<u8>,
    pub runtime_data: RuntimeData,
}

fn read_nv() -> Result<Vec<u8>> {
    let handle = NvIndexTpmHandle::new(VTPM_HCL_REPORT_NV_INDEX)
        .context("Unable to initialize TPM handle for HCL report NV index")?;
    let mut context = tss_esapi::Context::new(TctiNameConf::Device(DeviceConfig::default()))?;
    context.set_sessions((Some(AuthSession::Password), None, None));

    nv::read_full(&mut context, NvAuth::Owner, handle)
        .context("Unable to read HCL report from vTPM NV index")
}

pub fn read_report() -> Result<Report> {
    let isolation_type = get_isolation_type()
        .ok_or_else(|| anyhow!("Not running in an Azure CVM (Hyper-V isolation not detected)"))?;

    let data = read_nv()?;

    let header = HclHeader::parse(&data)?;

    let hw_report_size = match isolation_type {
        IsolationType::Snp => SNP_REPORT_SIZE,
        IsolationType::Tdx => TDX_REPORT_SIZE,
    };

    let hw_report_start = HCL_HEADER_SIZE;
    let hw_report_end = hw_report_start + hw_report_size;

    if data.len() < hw_report_end {
        return Err(anyhow!(
            "Data too small for hardware report: expected at least {} bytes, got {}",
            hw_report_end,
            data.len()
        ));
    }

    let hw_report = data[hw_report_start..hw_report_end].to_vec();

    let runtime_data = RuntimeData::parse(&data[hw_report_end..])?;

    let expected_report_type = match isolation_type {
        IsolationType::Snp => RUNTIME_DATA_REPORT_TYPE_SNP,
        IsolationType::Tdx => RUNTIME_DATA_REPORT_TYPE_TDX,
    };

    if runtime_data.report_type != expected_report_type {
        return Err(anyhow!(
            "Runtime data report type mismatch: expected {} for {:?}, got {}",
            expected_report_type,
            isolation_type,
            runtime_data.report_type
        ));
    }

    Ok(Report {
        header,
        isolation_type,
        hw_report,
        runtime_data,
    })
}
