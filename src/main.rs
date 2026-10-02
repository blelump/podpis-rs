use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use clap::Parser;
use num_bigint::BigUint;
use roxmltree::{Document, Node};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const TYPE_OBJECT: &str = "http://www.w3.org/2000/09/xmldsig#Object";
const TYPE_SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";

#[derive(Parser, Debug)]
#[command(
    name = "podpis-rs",
    version,
    about = "Validate the XAdES-BES enveloping XML signature"
)]
struct Args {
    #[arg(default_value = "a.xml")]
    path: std::path::PathBuf,
}

struct Check {
    name: String,
    ok: bool,
    expected: String,
    computed: String,
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

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args.path) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(path: &std::path::Path) -> Result<bool> {
    let xml =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let doc =
        Document::parse(&xml).with_context(|| format!("parsing XML in {}", path.display()))?;
    let root = doc.root_element();

    let mut checks = Vec::new();

    let content = check_content_digest(root, &mut checks)?;
    check_signed_properties_digest(root, &mut checks)?;

    let cert_der = cert_der(root)?;
    check_signature(root, &cert_der, &mut checks)?;
    check_cert_digest(root, &cert_der, &mut checks)?;

    println!("File: {}\n", path.display());
    let mut all_ok = true;
    for check in &checks {
        if check.ok {
            println!("[PASS] {}", check.name);
        } else {
            all_ok = false;
            println!("[FAIL] {}", check.name);
            if !check.expected.is_empty() {
                println!("         expected: {}", check.expected);
            }
            if !check.computed.is_empty() {
                println!("         computed: {}", check.computed);
            }
        }
    }

    let (_, cert) = X509Certificate::from_der(&cert_der).context("parsing signing certificate")?;
    println!("\nCertificate subject : {}", cert.subject());
    println!("Certificate issuer  : {}", cert.issuer());
    println!(
        "Certificate validity: {} -> {}",
        cert.validity().not_before,
        cert.validity().not_after
    );
    if let Some(t) = find_text(root, XADES, "SigningTime") {
        println!("Signing time        : {t}");
    }
    println!(
        "Signed content      : {:?}",
        String::from_utf8_lossy(&content)
    );

    println!(
        "\n=== {} ===",
        if all_ok {
            "ALL SIGNATURE CHECKS PASSED"
        } else {
            "VALIDATION FAILED"
        }
    );
    Ok(all_ok)
}

fn check_content_digest(root: Node, checks: &mut Vec<Check>) -> Result<Vec<u8>> {
    let reference = find_reference_by_type(root, TYPE_OBJECT)
        .ok_or_else(|| anyhow!("no {TYPE_OBJECT} reference found"))?;

    let uri = reference
        .attribute("URI")
        .ok_or_else(|| anyhow!("object reference has no URI"))?;
    let id = uri.strip_prefix('#').unwrap_or(uri);
    let object =
        find_by_id(root, DS, "Object", id).ok_or_else(|| anyhow!("no ds:Object with Id={id}"))?;

    let content = B64
        .decode(object.text().unwrap_or("").trim())
        .context("decoding base64 object content")?;

    let computed = B64.encode(Sha256::digest(&content));
    let expected = child_text(reference, DS, "DigestValue")
        .ok_or_else(|| anyhow!("object reference has no DigestValue"))?;

    checks.push(Check::new(
        "Reference #1 (document content) digest",
        computed == expected,
        expected,
        computed,
    ));
    Ok(content)
}

fn check_signed_properties_digest(root: Node, checks: &mut Vec<Check>) -> Result<()> {
    let reference = find_reference_by_type(root, TYPE_SIGNED_PROPERTIES)
        .ok_or_else(|| anyhow!("no {TYPE_SIGNED_PROPERTIES} reference found"))?;

    let uri = reference
        .attribute("URI")
        .ok_or_else(|| anyhow!("SignedProperties reference has no URI"))?;
    let id = uri.strip_prefix('#').unwrap_or(uri);
    let sp = find_by_id(root, XADES, "SignedProperties", id)
        .ok_or_else(|| anyhow!("no xades:SignedProperties with Id={id}"))?;

    let computed = B64.encode(Sha256::digest(exc_c14n(sp)?));
    let expected = child_text(reference, DS, "DigestValue")
        .ok_or_else(|| anyhow!("SignedProperties reference has no DigestValue"))?;

    checks.push(Check::new(
        "Reference #2 (SignedProperties) digest",
        computed == expected,
        expected,
        computed,
    ));
    Ok(())
}

fn check_signature(root: Node, cert_der: &[u8], checks: &mut Vec<Check>) -> Result<()> {
    let signed_info =
        child_element(root, DS, "SignedInfo").ok_or_else(|| anyhow!("no ds:SignedInfo"))?;
    let signature_value =
        find_text(root, DS, "SignatureValue").ok_or_else(|| anyhow!("no ds:SignatureValue"))?;
    let sig = B64
        .decode(signature_value.trim())
        .context("decoding SignatureValue")?;

    let key = rsa_public_key(cert_der)?;
    let sig_method = child_element(signed_info, DS, "SignatureMethod")
        .and_then(|n| n.attribute("Algorithm"))
        .ok_or_else(|| anyhow!("no ds:SignatureMethod"))?;
    let hash_name = sig_method.rsplit('-').next().unwrap_or("sha256");

    let name = format!("SignatureValue (RSA PKCS#1 v1.5 / {hash_name})");
    match verify_pkcs1v15(&key, &sig, &exc_c14n(signed_info)?, hash_name) {
        Ok(()) => checks.push(Check::new(name, true, "", "")),
        Err(err) => checks.push(Check::new(name, false, "", err.to_string())),
    }
    Ok(())
}

fn check_cert_digest(root: Node, cert_der: &[u8], checks: &mut Vec<Check>) -> Result<()> {
    let cert_digest =
        find_descendant(root, XADES, "CertDigest").ok_or_else(|| anyhow!("no xades:CertDigest"))?;
    let expected = child_text(cert_digest, DS, "DigestValue")
        .ok_or_else(|| anyhow!("xades:CertDigest has no DigestValue"))?;

    let computed = B64.encode(Sha512::digest(cert_der));
    checks.push(Check::new(
        "SigningCertificateV2 certificate digest (SHA-512)",
        computed == expected,
        expected,
        computed,
    ));
    Ok(())
}

struct RsaPublicKey {
    n: BigUint,
    e: BigUint,
}

fn rsa_public_key(cert_der: &[u8]) -> Result<RsaPublicKey> {
    let (_, cert) = X509Certificate::from_der(cert_der).context("parsing signing certificate")?;
    let rsa = cert
        .public_key()
        .parsed()
        .context("parsing subject public key info")?;
    let rsa = match rsa {
        PublicKey::RSA(k) => k,
        other => bail!("unsupported public key type: {other:?}"),
    };
    Ok(RsaPublicKey {
        n: BigUint::from_bytes_be(rsa.modulus),
        e: BigUint::from_bytes_be(rsa.exponent),
    })
}

fn verify_pkcs1v15(key: &RsaPublicKey, sig: &[u8], message: &[u8], hash_name: &str) -> Result<()> {
    let k = (key.n.bits() as usize).div_ceil(8);
    if sig.len() != k {
        bail!(
            "signature length {} does not match modulus length {}",
            sig.len(),
            k
        );
    }

    let mut block = BigUint::from_bytes_be(sig)
        .modpow(&key.e, &key.n)
        .to_bytes_be();
    if block.len() < k {
        let mut padded = vec![0u8; k - block.len()];
        padded.extend_from_slice(&block);
        block = padded;
    }

    if block.len() < 3 || block[0] != 0x00 || block[1] != 0x01 {
        bail!("invalid PKCS#1 v1.5 padding header");
    }
    let sep = block[2..]
        .iter()
        .position(|&b| b == 0x00)
        .map(|i| i + 2)
        .ok_or_else(|| anyhow!("no 0x00 separator in PKCS#1 v1.5 block"))?;
    let digest_info = &block[sep + 1..];

    let digest_len = match hash_name {
        "sha1" => 20,
        "sha256" => 32,
        "sha512" => 64,
        other => bail!("unsupported hash: {other}"),
    };
    if digest_info.len() < digest_len {
        bail!(
            "DigestInfo too short: {} bytes, need {digest_len}",
            digest_info.len()
        );
    }
    let embedded = &digest_info[digest_info.len() - digest_len..];

    let computed = digest_with(hash_name, message);
    if embedded != computed.as_slice() {
        bail!(
            "digest mismatch (embedded={}, computed={})",
            hex(embedded),
            hex(&computed)
        );
    }
    Ok(())
}

fn digest_with(hash_name: &str, data: &[u8]) -> Vec<u8> {
    match hash_name {
        "sha1" => Sha1::digest(data).to_vec(),
        "sha512" => Sha512::digest(data).to_vec(),
        _ => Sha256::digest(data).to_vec(),
    }
}

fn cert_der(root: Node) -> Result<Vec<u8>> {
    let text =
        find_text(root, DS, "X509Certificate").ok_or_else(|| anyhow!("no ds:X509Certificate"))?;
    B64.decode(text.trim()).context("decoding X509Certificate")
}

fn find_reference_by_type<'a>(root: Node<'a, 'a>, ref_type: &str) -> Option<Node<'a, 'a>> {
    root.descendants().find(|n| {
        n.is_element()
            && n.tag_name().name() == "Reference"
            && n.tag_name().namespace() == Some(DS)
            && n.attribute("Type") == Some(ref_type)
    })
}

fn find_by_id<'a>(root: Node<'a, 'a>, ns: &str, name: &str, id: &str) -> Option<Node<'a, 'a>> {
    root.descendants().find(|n| {
        n.is_element()
            && n.tag_name().name() == name
            && n.tag_name().namespace() == Some(ns)
            && (n.attribute("Id") == Some(id) || n.attribute("ID") == Some(id))
    })
}

fn find_descendant<'a>(root: Node<'a, 'a>, ns: &str, name: &str) -> Option<Node<'a, 'a>> {
    root.descendants().find(|n| {
        n.is_element() && n.tag_name().name() == name && n.tag_name().namespace() == Some(ns)
    })
}

fn child_element<'a>(node: Node<'a, 'a>, ns: &str, name: &str) -> Option<Node<'a, 'a>> {
    node.children().find(|n| {
        n.is_element() && n.tag_name().name() == name && n.tag_name().namespace() == Some(ns)
    })
}

fn child_text<'a>(node: Node<'a, 'a>, ns: &str, name: &str) -> Option<String> {
    child_element(node, ns, name)
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
}

fn find_text(root: Node, ns: &str, name: &str) -> Option<String> {
    find_descendant(root, ns, name)
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn exc_c14n(node: Node) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut ns_stack: Vec<Vec<(String, String)>> = Vec::new();
    write_c14n(node, &mut out, &mut ns_stack)?;
    Ok(out)
}

fn in_scope_ns(node: Node) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = node
        .namespaces()
        .map(|ns| (ns.name().unwrap_or("").to_string(), ns.uri().to_string()))
        .collect();
    v.sort();
    v.dedup();
    v
}

fn write_c14n(
    node: Node,
    out: &mut Vec<u8>,
    ns_stack: &mut Vec<Vec<(String, String)>>,
) -> Result<()> {
    match node.node_type() {
        roxmltree::NodeType::Root => {
            for child in node.children() {
                write_c14n(child, out, ns_stack)?;
            }
        }
        roxmltree::NodeType::Element => write_element(node, out, ns_stack)?,
        roxmltree::NodeType::Text => {
            out.extend_from_slice(escape_text(node.text().unwrap_or("")).as_bytes());
        }
        _ => {}
    }
    Ok(())
}

fn write_element(
    node: Node,
    out: &mut Vec<u8>,
    ns_stack: &mut Vec<Vec<(String, String)>>,
) -> Result<()> {
    let scope: Vec<(String, String)> = in_scope_ns(node);

    let qname = qualified_name(node);
    let parent_scope: Vec<(String, String)> = ns_stack.last().cloned().unwrap_or_default();

    let mut used: Vec<String> = Vec::new();
    let prefix = prefix_of(&qname);
    used.push(prefix);
    for attr in node.attributes() {
        if attr.namespace().is_none() {
            continue;
        }
        if let Some(p) = attr
            .name()
            .split(':')
            .next()
            .filter(|p| !p.is_empty() && *p != "xmlns")
        {
            used.push(p.to_string());
        }
    }
    used.sort();
    used.dedup();

    out.extend_from_slice(b"<");
    out.extend_from_slice(qname.as_bytes());

    let mut emitted: Vec<(String, String)> = Vec::new();
    for prefix in &used {
        if let Some((_, uri)) = scope.iter().find(|(p, _)| p == prefix) {
            if !parent_scope.iter().any(|(p, u)| p == prefix && u == uri) {
                emitted.push((prefix.clone(), uri.clone()));
            }
        }
    }
    emitted.sort();
    for (prefix, uri) in &emitted {
        if prefix.is_empty() {
            out.extend_from_slice(b" xmlns=\"");
        } else {
            out.extend_from_slice(format!(" xmlns:{prefix}=\"").as_bytes());
        }
        out.extend_from_slice(escape_attr(uri).as_bytes());
        out.extend_from_slice(b"\"");
    }

    let mut attrs: Vec<(String, String, String)> = node
        .attributes()
        .filter(|a| a.name() != "xmlns" && !a.name().starts_with("xmlns:"))
        .map(|a| {
            (
                a.namespace().unwrap_or("").to_string(),
                a.name().to_string(),
                a.value().to_string(),
            )
        })
        .collect();
    attrs.sort();
    for (_, name, value) in &attrs {
        out.extend_from_slice(b" ");
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"=\"");
        out.extend_from_slice(escape_attr(value).as_bytes());
        out.extend_from_slice(b"\"");
    }

    out.push(b'>');
    let mut rendered_scope = parent_scope.clone();
    for binding in &emitted {
        rendered_scope.retain(|(p, _)| p != &binding.0);
        rendered_scope.push(binding.clone());
    }
    rendered_scope.sort();
    ns_stack.push(rendered_scope);

    if node.children().next().is_none() {
        out.extend_from_slice(format!("</{qname}>").as_bytes());
    } else {
        for child in node.children() {
            write_c14n(child, out, ns_stack)?;
        }
        out.extend_from_slice(format!("</{qname}>").as_bytes());
    }

    ns_stack.pop();
    Ok(())
}

fn prefix_of(qname: &str) -> String {
    match qname.split_once(':') {
        Some((p, _)) => p.to_string(),
        None => String::new(),
    }
}

fn qualified_name(node: Node) -> String {
    let name = node.tag_name().name();
    if let Some(prefix) = node.lookup_prefix(node.tag_name().namespace().unwrap_or("")) {
        if !prefix.is_empty() {
            return format!("{prefix}:{name}");
        }
    }
    name.to_string()
}

fn escape_text(s: &str) -> String {
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attr(s: &str) -> String {
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
}
