use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::{Any, ObjectIdentifier, OctetString, SequenceOf};
use der::{Decode, Encode, Sequence};
use lopdf::Object;
use rsa::pkcs1v15::Signature;
use rsa::pkcs8::DecodePublicKey;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attribute;
use x509_parser::prelude::*;

use crate::{digest_for, verify_pkcs1v15, Check, Validation};

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const OID_RSA_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const OID_SIGNING_CERT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
const OID_SIGNING_CERT_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

#[derive(Sequence)]
struct EssCertIdV2 {
    #[asn1(optional = "true")]
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    #[asn1(optional = "true")]
    issuer_serial: Option<Any>,
}

#[derive(Sequence)]
struct EssCertId {
    cert_hash: OctetString,
    #[asn1(optional = "true")]
    issuer_serial: Option<Any>,
}

#[derive(Sequence)]
struct SigningCertificateV2 {
    certs: SequenceOf<EssCertIdV2, 16>,
    #[asn1(optional = "true")]
    policies: Option<Any>,
}

#[derive(Sequence)]
struct SigningCertificate {
    certs: SequenceOf<EssCertId, 16>,
    #[asn1(optional = "true")]
    policies: Option<Any>,
}

type ByteRanges = Vec<(usize, usize)>;

pub fn validate_pdf(data: &[u8]) -> Result<Validation> {
    let (ranges, cms) = find_signature(data)?;
    let mut checks = Vec::new();

    let covered = covered_bytes(data, &ranges)?;

    let cms_len = cms.len();
    let cms = &cms[..der_total_len(&cms)?];
    let info = ContentInfo::from_der(cms).context("parsing CMS ContentInfo")?;
    if info.content_type != OID_SIGNED_DATA {
        bail!("unexpected CMS content type: {}", info.content_type);
    }
    let sd: SignedData = info.content.decode_as().context("parsing CMS SignedData")?;
    let signer = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow!("no SignerInfo in CMS"))?;

    let digest_name = match &signer.digest_alg.oid {
        oid if *oid == OID_SHA1 => "sha1",
        oid if *oid == OID_SHA256 => "sha256",
        oid if *oid == OID_SHA512 => "sha512",
        other => bail!("unsupported PAdES digest algorithm: {other}"),
    };

    let attrs: &[Attribute] = signer
        .signed_attrs
        .as_ref()
        .map(|a| a.as_slice())
        .unwrap_or(&[]);

    if let Some(md) = attr_value(attrs, OID_MESSAGE_DIGEST) {
        let expected = md.value().to_vec();
        let computed = digest_for(digest_name, &covered)?;
        checks.push(Check::new(
            "messageDigest signed attribute (PAdES covered bytes)",
            computed == expected,
            B64.encode(&expected),
            B64.encode(&computed),
        ));
    }

    let message = match &signer.signed_attrs {
        Some(a) => a.to_der().context("re-encoding signed attributes")?,
        None => covered,
    };

    let hash_name = match &signer.signature_algorithm.oid {
        oid if *oid == OID_RSA_SHA1 => "sha1",
        oid if *oid == OID_RSA_SHA256 => "sha256",
        oid if *oid == OID_RSA_SHA512 => "sha512",
        other => bail!("unsupported PAdES signature algorithm: {other}"),
    };
    let sig = Signature::try_from(signer.signature.as_bytes())
        .context("decoding PKCS#1 v1.5 signature")?;

    let certs = collect_certs(&sd)?;

    let ess = ess_cert_digest(attrs)?;
    let mut candidates: Vec<usize> = Vec::new();
    if let Some((alg, hash)) = &ess {
        for (i, der) in certs.iter().enumerate() {
            if digest_for(alg, der).is_ok_and(|d| d == *hash) {
                candidates.push(i);
                break;
            }
        }
    }
    for i in 0..certs.len() {
        if !candidates.contains(&i) {
            candidates.push(i);
        }
    }

    let mut signer_idx = candidates[0];
    let mut ok = false;
    for &i in &candidates {
        let (_, cert) = X509Certificate::from_der(&certs[i]).context("parsing certificate")?;
        let key = match rsa::RsaPublicKey::from_public_key_der(cert.public_key().raw) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let verified = match hash_name {
            "sha1" => verify_pkcs1v15::<Sha1>(&key, &sig, &message, "sha1"),
            "sha256" => verify_pkcs1v15::<Sha256>(&key, &sig, &message, "sha256"),
            "sha512" => verify_pkcs1v15::<Sha512>(&key, &sig, &message, "sha512"),
            _ => unreachable!(),
        };
        if verified.is_ok() {
            ok = true;
            signer_idx = i;
            break;
        }
    }

    if let Some((alg, hash)) = &ess {
        let label = if alg == "sha1" && is_ess_v1(attrs) {
            "SigningCertificate"
        } else {
            "SigningCertificateV2"
        };
        let computed = digest_for(alg, &certs[signer_idx])?;
        checks.push(Check::new(
            format!("{label} certificate digest ({alg})"),
            computed == *hash,
            B64.encode(hash),
            B64.encode(&computed),
        ));
    }

    checks.push(Check::new(
        format!("SignatureValue (CAdES RSA PKCS#1 v1.5 / {hash_name})"),
        ok,
        "",
        if ok {
            String::new()
        } else {
            "digest mismatch or invalid padding".to_string()
        },
    ));

    let (_, cert) =
        X509Certificate::from_der(&certs[signer_idx]).context("parsing signing certificate")?;

    let signing_time = attr_value(attrs, OID_SIGNING_TIME).and_then(|a| format_time(a.value()));

    let (hex_start, hex_end) = locate_hex(data, cms_len * 2)?;
    let mut content = data.to_vec();
    for b in &mut content[hex_start..hex_end] {
        *b = b'0';
    }

    Ok(Validation {
        checks,
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        signing_time,
        content,
    })
}

fn find_signature(data: &[u8]) -> Result<(ByteRanges, Vec<u8>)> {
    let doc = lopdf::Document::load_from(data).context("parsing PDF")?;
    for obj in doc.objects.values() {
        let dict = match obj {
            Object::Dictionary(d) => d,
            Object::Stream(s) => &s.dict,
            _ => continue,
        };
        let Ok(br) = dict.get(b"ByteRange") else {
            continue;
        };
        let br = doc.dereference(br)?.1;
        let arr = br.as_array().context("malformed /ByteRange")?;
        let mut ranges = Vec::new();
        for pair in arr.chunks(2) {
            if pair.len() != 2 {
                bail!("malformed /ByteRange");
            }
            let (off, len) = (pair[0].as_i64()?, pair[1].as_i64()?);
            if off < 0 || len < 0 {
                bail!("malformed /ByteRange");
            }
            ranges.push((off as usize, len as usize));
        }
        let subfilter = dict
            .get(b"SubFilter")
            .ok()
            .and_then(|o| doc.dereference(o).ok())
            .and_then(|(_, o)| o.as_name().ok().map(|b| b.to_vec()));
        if subfilter.as_deref() == Some(b"ETSI.RFC3161".as_slice()) {
            bail!("DocTimeStamp (ETSI.RFC3161) signatures are not supported");
        }
        let contents = doc.dereference(dict.get(b"Contents")?)?.1;
        let cms = contents.as_str().context("malformed /Contents")?.to_vec();
        return Ok((ranges, cms));
    }
    bail!("no PDF signature (/ByteRange) found — file is not signed");
}

fn covered_bytes(data: &[u8], ranges: &ByteRanges) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for &(off, len) in ranges {
        let end = off
            .checked_add(len)
            .ok_or_else(|| anyhow!("ByteRange overflow"))?;
        if end > data.len() {
            bail!("ByteRange [{off} {len}] exceeds file size {}", data.len());
        }
        out.extend_from_slice(&data[off..end]);
    }
    Ok(out)
}

fn collect_certs(sd: &SignedData) -> Result<Vec<Vec<u8>>> {
    let set = sd
        .certificates
        .as_ref()
        .ok_or_else(|| anyhow!("no certificates in CMS"))?;
    let mut out = Vec::new();
    for choice in set.0.as_slice() {
        match choice {
            CertificateChoices::Certificate(cert) => {
                out.push(cert.to_der().context("re-encoding certificate")?);
            }
            CertificateChoices::Other(_) => bail!("unsupported certificate choice in CMS"),
        }
    }
    if out.is_empty() {
        bail!("no certificates in CMS");
    }
    Ok(out)
}

fn attr_value(attrs: &[Attribute], oid: ObjectIdentifier) -> Option<&Any> {
    attrs
        .iter()
        .find(|a| a.oid == oid)?
        .values
        .as_slice()
        .first()
}

fn ess_cert_digest(attrs: &[Attribute]) -> Result<Option<(String, Vec<u8>)>> {
    if let Some(v) = attr_value(attrs, OID_SIGNING_CERT_V2) {
        let scv2 = v
            .decode_as::<SigningCertificateV2>()
            .context("parsing SigningCertificateV2")?;
        let first = scv2
            .certs
            .iter()
            .next()
            .ok_or_else(|| anyhow!("empty SigningCertificateV2"))?;
        let alg = match &first.hash_algorithm {
            Some(a) => oid_digest_name(&a.oid)?.to_string(),
            None => "sha256".to_string(),
        };
        return Ok(Some((alg, first.cert_hash.as_bytes().to_vec())));
    }
    if let Some(v) = attr_value(attrs, OID_SIGNING_CERT) {
        let sc = v
            .decode_as::<SigningCertificate>()
            .context("parsing SigningCertificate")?;
        let first = sc
            .certs
            .iter()
            .next()
            .ok_or_else(|| anyhow!("empty SigningCertificate"))?;
        return Ok(Some((
            "sha1".to_string(),
            first.cert_hash.as_bytes().to_vec(),
        )));
    }
    Ok(None)
}

fn is_ess_v1(attrs: &[Attribute]) -> bool {
    attr_value(attrs, OID_SIGNING_CERT).is_some()
}

fn oid_digest_name(oid: &ObjectIdentifier) -> Result<&'static str> {
    if *oid == OID_SHA1 {
        Ok("sha1")
    } else if *oid == OID_SHA256 {
        Ok("sha256")
    } else if *oid == OID_SHA512 {
        Ok("sha512")
    } else {
        bail!("unsupported digest algorithm: {oid}")
    }
}

fn format_time(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    let (year, rest) = match s.len() {
        13 if s.ends_with('Z') => (format!("20{}", &s[..2]), &s[2..]),
        15 if s.ends_with('Z') => (s[..4].to_string(), &s[4..]),
        _ => return Some(s.to_string()),
    };
    Some(format!(
        "{year}-{}-{}T{}:{}:{}Z",
        &rest[0..2],
        &rest[2..4],
        &rest[4..6],
        &rest[6..8],
        &rest[8..10]
    ))
}

fn der_total_len(data: &[u8]) -> Result<usize> {
    if data.len() < 2 {
        bail!("truncated DER");
    }
    let mut idx = 2usize;
    let mut len = data[1] as usize;
    if data[1] & 0x80 != 0 {
        let n = (data[1] & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < idx + n {
            bail!("malformed DER header");
        }
        idx += n;
        len = 0;
        for &b in &data[2..idx] {
            len = (len << 8) | b as usize;
        }
    }
    if idx + len > data.len() {
        bail!("DER length exceeds data");
    }
    Ok(idx + len)
}

fn locate_hex(data: &[u8], hex_len: usize) -> Result<(usize, usize)> {
    let mut from = 0;
    while let Some(i) = find_sub(data, from, b"/Contents") {
        from = i + 1;
        let mut j = i + 9;
        while j < data.len() && data[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= data.len() || data[j] != b'<' {
            continue;
        }
        let start = j + 1;
        let mut k = start;
        let mut n = 0;
        while k < data.len() && data[k] != b'>' {
            if data[k].is_ascii_hexdigit() {
                n += 1;
            }
            k += 1;
        }
        if k < data.len() && n == hex_len {
            return Ok((start, k));
        }
    }
    bail!("cannot locate /Contents hex placeholder");
}

fn find_sub(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}
