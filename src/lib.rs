mod pades;
mod xades;

pub use xades::{validate_str, DS, XADES};

use anyhow::{bail, Context, Result};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::hazmat::PrehashVerifier;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub expected: String,
    pub computed: String,
}

impl Check {
    fn new(
        name: impl Into<String>,
        ok: bool,
        expected: impl Into<String>,
        computed: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            ok,
            expected: expected.into(),
            computed: computed.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Validation {
    pub checks: Vec<Check>,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub signing_time: Option<String>,
    pub content: Vec<u8>,
}

impl Validation {
    pub fn all_passed(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
}

pub fn validate(path: &std::path::Path) -> Result<Validation> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if data.starts_with(b"%PDF-") {
        return pades::validate_pdf(&data);
    }
    let xml = std::str::from_utf8(&data)
        .map_err(|_| anyhow::anyhow!("{} is not an XML or PDF file", path.display()))?;
    xades::validate_str(xml)
}

pub fn digest_for(algorithm: &str, data: &[u8]) -> Result<Vec<u8>> {
    match algorithm.rsplit('#').next().unwrap_or("") {
        "sha1" => Ok(Sha1::digest(data).to_vec()),
        "sha256" => Ok(Sha256::digest(data).to_vec()),
        "sha512" => Ok(Sha512::digest(data).to_vec()),
        other => bail!("unsupported digest algorithm: {other}"),
    }
}

pub(crate) fn verify_pkcs1v15<D>(
    key: &rsa::RsaPublicKey,
    sig: &Signature,
    message: &[u8],
    hash_name: &str,
) -> Result<()>
where
    D: Digest,
    VerifyingKey<D>: PrehashVerifier<Signature>,
{
    let digest = D::digest(message);
    let vkey = VerifyingKey::<D>::new_unprefixed(key.clone());
    for null_params in [true, false] {
        let mut digest_info = digest_info_prefix(hash_name, null_params)?;
        digest_info.extend_from_slice(&digest);
        if vkey.verify_prehash(&digest_info, sig).is_ok() {
            return Ok(());
        }
    }
    bail!("digest mismatch or invalid padding")
}

fn digest_info_prefix(hash_name: &str, null_params: bool) -> Result<Vec<u8>> {
    let (oid, digest_len) = match hash_name {
        "sha1" => ("06052b0e03021a", 20),
        "sha256" => ("0609608648016503040201", 32),
        "sha512" => ("0609608648016503040203", 64),
        other => bail!("unsupported hash: {other}"),
    };
    let params = if null_params { "0500" } else { "" };
    let alg_len = oid.len() / 2 + params.len() / 2;
    let di_len = 2 + alg_len + 2 + digest_len;
    let hex = format!("30{di_len:02x}30{alg_len:02x}{oid}{params}04{digest_len:02x}");
    Ok((0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex constant"))
        .collect())
}
