use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use num_bigint::BigUint;
use roxmltree::{Document, Node};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const TYPE_OBJECT: &str = "http://www.w3.org/2000/09/xmldsig#Object";
const TYPE_SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";
const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA512_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const TRANSFORM_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const TRANSFORM_FILTER2: &str = "http://www.w3.org/2002/06/xmldsig-filter2";

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
    let xml =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    validate_str(&xml)
}

pub fn validate_str(xml: &str) -> Result<Validation> {
    let doc = Document::parse(xml).context("parsing XML")?;
    let root = doc.root_element();

    let mut checks = Vec::new();

    let content = check_content_digest(root, &mut checks)?;
    check_signed_properties_digest(root, &mut checks)?;

    let cert_der = cert_der(root)?;
    check_signature(root, &cert_der, &mut checks)?;
    check_cert_digest(root, &cert_der, &mut checks)?;

    let (_, cert) = X509Certificate::from_der(&cert_der).context("parsing signing certificate")?;

    Ok(Validation {
        checks,
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        signing_time: find_text(root, XADES, "SigningTime"),
        content,
    })
}

fn check_content_digest(root: Node, checks: &mut Vec<Check>) -> Result<Vec<u8>> {
    if let Some(reference) = find_reference_by_type(root, TYPE_OBJECT) {
        return enveloping_content(root, reference, checks);
    }
    let reference = find_enveloped_reference(root)?
        .ok_or_else(|| anyhow!("no ds:Reference covering the document content found"))?;
    enveloped_content(root, reference, checks)
}

/// Reference with `Type="...#Object"` pointing at a `ds:Object` holding the
/// base64-encoded content (enveloping signature).
fn enveloping_content(root: Node, reference: Node, checks: &mut Vec<Check>) -> Result<Vec<u8>> {
    let uri = reference
        .attribute("URI")
        .ok_or_else(|| anyhow!("object reference has no URI"))?;
    let id = uri.strip_prefix('#').unwrap_or(uri);
    let object =
        find_by_id(root, DS, "Object", id).ok_or_else(|| anyhow!("no ds:Object with Id={id}"))?;

    let content = B64
        .decode(object.text().unwrap_or("").trim())
        .context("decoding base64 object content")?;

    let method = child_digest_algorithm(reference);
    let computed = B64.encode(digest_for(&method, &content)?);
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

/// Reference with `URI=""` covering the whole document with every embedded
/// `ds:Signature` removed (enveloped signature, ePUAP "PodpisanyPlik" style).
fn find_enveloped_reference<'a>(root: Node<'a, 'a>) -> Result<Option<Node<'a, 'a>>> {
    let Some(reference) = root.descendants().find(|n| {
        n.is_element()
            && n.tag_name().name() == "Reference"
            && n.tag_name().namespace() == Some(DS)
            && n.attribute("Type").is_none()
            && n.attribute("URI") == Some("")
    }) else {
        return Ok(None);
    };

    let transforms = child_element(reference, DS, "Transforms")
        .map(|t| {
            t.children()
                .filter(|n| {
                    n.is_element()
                        && n.tag_name().name() == "Transform"
                        && n.tag_name().namespace() == Some(DS)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if transforms.is_empty() {
        bail!("content reference has no ds:Transforms");
    }
    for transform in transforms {
        match transform.attribute("Algorithm").unwrap_or("") {
            TRANSFORM_ENVELOPED => {}
            TRANSFORM_FILTER2 => {
                let subtracts_signature = transform.descendants().any(|n| {
                    n.is_element()
                        && n.tag_name().name() == "XPath"
                        && n.attribute("Filter") == Some("subtract")
                        && n.text().is_some_and(|t| t.contains("Signature"))
                });
                if !subtracts_signature {
                    bail!("unsupported xmldsig-filter2 transform");
                }
            }
            other => bail!("unsupported content reference transform: {other}"),
        }
    }
    Ok(Some(reference))
}

fn enveloped_content(root: Node, reference: Node, checks: &mut Vec<Check>) -> Result<Vec<u8>> {
    let expected = child_text(reference, DS, "DigestValue")
        .ok_or_else(|| anyhow!("content reference has no DigestValue"))?;
    let method = child_digest_algorithm(reference);

    let remove_signature = |n: &Node| {
        n.is_element() && n.tag_name().name() == "Signature" && n.tag_name().namespace() == Some(DS)
    };
    // The SignedInfo CanonicalizationMethod says exc-c14n, but ePUAP
    // "PodpisanyPlik" signers digest the document inclusively; accept either.
    let signed_doc = exc_c14n_if(root, &remove_signature)?;
    let signed_doc_inclusive = inclusive_c14n_if(root, &remove_signature)?;
    let computed_exc = B64.encode(digest_for(&method, &signed_doc)?);
    let computed_inclusive = B64.encode(digest_for(&method, &signed_doc_inclusive)?);

    let computed = if computed_exc == expected {
        computed_exc
    } else {
        computed_inclusive
    };
    checks.push(Check::new(
        "Reference #1 (enveloped document) digest",
        computed == expected,
        expected,
        computed,
    ));

    // ePUAP documents carry the payload as base64 attachments; fall back to
    // the canonical document itself.
    let mut content: Vec<u8> = root
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "DaneZalacznika")
        .map(|attachment| -> Result<Vec<u8>> {
            let text: String = attachment
                .text()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            B64.decode(text).context("decoding base64 attachment")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    if content.is_empty() {
        content = signed_doc;
    }
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

    let computed = B64.encode(digest_for(
        &child_digest_algorithm(reference),
        &exc_c14n(sp)?,
    )?);
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
        find_descendant(root, DS, "SignedInfo").ok_or_else(|| anyhow!("no ds:SignedInfo"))?;
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

    let method = child_element(cert_digest, DS, "DigestMethod")
        .and_then(|n| n.attribute("Algorithm"))
        .unwrap_or(SHA512_URI);
    let hash = method.rsplit('#').next().unwrap_or("sha512");
    let computed = B64.encode(digest_for(method, cert_der)?);
    checks.push(Check::new(
        format!("SigningCertificateV2 certificate digest ({hash})"),
        computed == expected,
        expected,
        computed,
    ));
    Ok(())
}

#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

pub fn rsa_public_key(cert_der: &[u8]) -> Result<RsaPublicKey> {
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

pub fn verify_pkcs1v15(
    key: &RsaPublicKey,
    sig: &[u8],
    message: &[u8],
    hash_name: &str,
) -> Result<()> {
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

/// Hashes `data` according to a `DigestMethod` algorithm URI.
pub fn digest_for(algorithm: &str, data: &[u8]) -> Result<Vec<u8>> {
    match algorithm.rsplit('#').next().unwrap_or("") {
        "sha1" => Ok(Sha1::digest(data).to_vec()),
        "sha256" => Ok(Sha256::digest(data).to_vec()),
        "sha512" => Ok(Sha512::digest(data).to_vec()),
        other => bail!("unsupported digest algorithm: {other}"),
    }
}

/// Algorithm URI of a reference's (or other node's) `ds:DigestMethod` child.
/// Defaults to SHA-256 for legacy documents without one.
fn child_digest_algorithm(node: Node) -> String {
    child_element(node, DS, "DigestMethod")
        .and_then(|n| n.attribute("Algorithm"))
        .unwrap_or(SHA256_URI)
        .to_string()
}

fn cert_der(root: Node) -> Result<Vec<u8>> {
    let text =
        find_text(root, DS, "X509Certificate").ok_or_else(|| anyhow!("no ds:X509Certificate"))?;
    B64.decode(text.trim()).context("decoding X509Certificate")
}

pub fn find_reference_by_type<'a>(root: Node<'a, 'a>, ref_type: &str) -> Option<Node<'a, 'a>> {
    root.descendants().find(|n| {
        n.is_element()
            && n.tag_name().name() == "Reference"
            && n.tag_name().namespace() == Some(DS)
            && n.attribute("Type") == Some(ref_type)
    })
}

pub fn find_by_id<'a>(root: Node<'a, 'a>, ns: &str, name: &str, id: &str) -> Option<Node<'a, 'a>> {
    root.descendants().find(|n| {
        n.is_element()
            && n.tag_name().name() == name
            && n.tag_name().namespace() == Some(ns)
            && (n.attribute("Id") == Some(id) || n.attribute("ID") == Some(id))
    })
}

pub fn find_descendant<'a>(root: Node<'a, 'a>, ns: &str, name: &str) -> Option<Node<'a, 'a>> {
    root.descendants().find(|n| {
        n.is_element() && n.tag_name().name() == name && n.tag_name().namespace() == Some(ns)
    })
}

pub fn child_element<'a>(node: Node<'a, 'a>, ns: &str, name: &str) -> Option<Node<'a, 'a>> {
    node.children().find(|n| {
        n.is_element() && n.tag_name().name() == name && n.tag_name().namespace() == Some(ns)
    })
}

pub fn child_text<'a>(node: Node<'a, 'a>, ns: &str, name: &str) -> Option<String> {
    child_element(node, ns, name)
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
}

pub fn find_text(root: Node, ns: &str, name: &str) -> Option<String> {
    find_descendant(root, ns, name)
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub fn exc_c14n(node: Node) -> Result<Vec<u8>> {
    c14n(node, &|_| false, false)
}

/// Canonicalizes like [`exc_c14n`], omitting the subtrees matched by `skip`
/// (used to strip embedded signatures for enveloped-signature references).
pub fn exc_c14n_if(node: Node, skip: &dyn Fn(&Node) -> bool) -> Result<Vec<u8>> {
    c14n(node, skip, false)
}

/// Exclusive c14n keeps namespace declarations only where they are visibly
/// utilized; inclusive C14N 1.0 keeps them where the document declares them.
/// Some signers (e.g. the ePUAP enveloped "PodpisanyPlik" flavor) digest the
/// document inclusively, so both are offered.
pub fn inclusive_c14n_if(node: Node, skip: &dyn Fn(&Node) -> bool) -> Result<Vec<u8>> {
    c14n(node, skip, true)
}

fn c14n(node: Node, skip: &dyn Fn(&Node) -> bool, inclusive: bool) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut ns_stack: Vec<Vec<(String, String)>> = Vec::new();
    write_c14n(node, &mut out, &mut ns_stack, skip, inclusive)?;
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
    skip: &dyn Fn(&Node) -> bool,
    inclusive: bool,
) -> Result<()> {
    match node.node_type() {
        roxmltree::NodeType::Root => {
            for child in node.children() {
                write_c14n(child, out, ns_stack, skip, inclusive)?;
            }
        }
        roxmltree::NodeType::Element => {
            if !skip(&node) {
                write_element(node, out, ns_stack, skip, inclusive)?;
            }
        }
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
    skip: &dyn Fn(&Node) -> bool,
    inclusive: bool,
) -> Result<()> {
    let scope: Vec<(String, String)> = in_scope_ns(node);
    let qname = qualified_name(node);
    let parent_scope: Vec<(String, String)> = ns_stack.last().cloned().unwrap_or_default();

    let mut attr_qnames: Vec<(String, String)> = node
        .attributes()
        .filter(|a| a.name() != "xmlns" && !a.name().starts_with("xmlns:"))
        .map(|a| {
            let ns_uri = a.namespace().unwrap_or("").to_string();
            let local = a.name().to_string();
            let qn = match a.namespace().and_then(|uri| node.lookup_prefix(uri)) {
                Some(p) if !p.is_empty() => format!("{p}:{local}"),
                _ => local,
            };
            (ns_uri, qn)
        })
        .collect();
    // Canonical XML sorts attributes by (namespace URI, local name).
    attr_qnames.sort();

    let mut emitted: Vec<(String, String)> = Vec::new();
    if inclusive {
        // C14N 1.0: output namespace declarations where the document declares
        // them, not where they are first visibly utilized.
        let parent: Vec<(String, String)> = node.parent().map(in_scope_ns).unwrap_or_default();
        emitted = in_scope_ns(node)
            .into_iter()
            .filter(|binding| !parent.contains(binding))
            .collect();
    } else {
        let mut used: Vec<String> = Vec::new();
        used.push(prefix_of(&qname));
        for (ns_uri, _) in &attr_qnames {
            if let Some(p) = scope.iter().find(|(_, u)| u == ns_uri) {
                used.push(p.0.clone());
            }
        }
        used.sort();
        used.dedup();

        for prefix in &used {
            if let Some((_, uri)) = scope.iter().find(|(p, _)| p == prefix) {
                if !parent_scope.iter().any(|(p, u)| p == prefix && u == uri) {
                    emitted.push((prefix.clone(), uri.clone()));
                }
            }
        }
        emitted.sort();
    }
    out.extend_from_slice(b"<");
    out.extend_from_slice(qname.as_bytes());

    for (prefix, uri) in &emitted {
        if prefix.is_empty() {
            out.extend_from_slice(b" xmlns=\"");
        } else {
            out.extend_from_slice(format!(" xmlns:{prefix}=\"").as_bytes());
        }
        out.extend_from_slice(escape_attr(uri).as_bytes());
        out.extend_from_slice(b"\"");
    }

    for (ns_uri, qn) in &attr_qnames {
        let local = qn.split(':').next_back().unwrap_or(qn);
        let value = node
            .attributes()
            .find(|a| a.name() == local && a.namespace().unwrap_or("") == ns_uri)
            .map(|a| a.value())
            .unwrap_or("");
        out.extend_from_slice(b" ");
        out.extend_from_slice(qn.as_bytes());
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
            write_c14n(child, out, ns_stack, skip, inclusive)?;
        }
        out.extend_from_slice(format!("</{qname}>").as_bytes());
    }

    ns_stack.pop();
    Ok(())
}

pub fn prefix_of(qname: &str) -> String {
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

pub fn escape_text(s: &str) -> String {
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn escape_attr(s: &str) -> String {
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
}
