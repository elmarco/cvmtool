// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Deserialize;

// https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design#runtime-claims

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct RuntimeClaimsKey {
    pub kid: String,
    #[serde(default)]
    pub key_ops: Vec<String>,
    pub kty: String,
    pub e: Option<String>,
    pub n: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
pub struct VmConfiguration {
    pub root_cert_thumbprint: Option<String>,
    pub console_enabled: Option<bool>,
    pub secure_boot: Option<bool>,
    pub tpm_enabled: Option<bool>,
    pub tpm_persisted: Option<bool>,
    #[serde(rename = "vmUniqueId")]
    pub vm_unique_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
pub struct RuntimeClaims {
    #[serde(default)]
    pub keys: Vec<RuntimeClaimsKey>,
    pub vm_configuration: Option<VmConfiguration>,
    pub user_data: Option<String>,
}
