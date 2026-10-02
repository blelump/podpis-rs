use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use roxmltree::{Document, Node};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::hazmat::PrehashVerifier;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use x509_parser::prelude::*;

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
    let sig = Signature::try_from(sig.as_slice()).context("decoding PKCS#1 v1.5 signature")?;

    let (_, cert) = X509Certificate::from_der(cert_der).context("parsing signing certificate")?;
    let key = rsa::RsaPublicKey::from_public_key_der(cert.public_key().raw)
        .map_err(|err| anyhow!("invalid RSA public key: {err}"))?;

    let sig_method = child_element(signed_info, DS, "SignatureMethod")
        .and_then(|n| n.attribute("Algorithm"))
        .ok_or_else(|| anyhow!("no ds:SignatureMethod"))?;
    let hash_name = sig_method.rsplit('-').next().unwrap_or("sha256");

    let message = exc_c14n(signed_info)?;
    let result = match hash_name {
        "sha1" => verify_pkcs1v15::<Sha1>(&key, &sig, &message, hash_name),
        "sha256" => verify_pkcs1v15::<Sha256>(&key, &sig, &message, hash_name),
        "sha512" => verify_pkcs1v15::<Sha512>(&key, &sig, &message, hash_name),
        other => bail!("unsupported hash: {other}"),
    };

    let name = format!("SignatureValue (RSA PKCS#1 v1.5 / {hash_name})");
    match result {
        Ok(()) => checks.push(Check::new(name, true, "", "")),
        Err(err) => checks.push(Check::new(name, false, "", err.to_string())),
    }
    Ok(())
}

fn verify_pkcs1v15<D>(
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

pub fn digest_for(algorithm: &str, data: &[u8]) -> Result<Vec<u8>> {
    match algorithm.rsplit('#').next().unwrap_or("") {
        "sha1" => Ok(Sha1::digest(data).to_vec()),
        "sha256" => Ok(Sha256::digest(data).to_vec()),
        "sha512" => Ok(Sha512::digest(data).to_vec()),
        other => bail!("unsupported digest algorithm: {other}"),
    }
}

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

pub fn exc_c14n(node: Node) -> Result<Vec<u8>> {
    c14n(node, &|_| false, false)
}

pub fn exc_c14n_if(node: Node, skip: &dyn Fn(&Node) -> bool) -> Result<Vec<u8>> {
    c14n(node, skip, false)
}

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
    attr_qnames.sort();

    let mut emitted: Vec<(String, String)> = Vec::new();
    if inclusive {
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
