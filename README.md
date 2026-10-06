# podpis-rs

Verifies signatures of [podpis.gov.pl](https://podpis.gov.pl) artifacts.

Supported formats:

- **XAdES-BES** (XML), both ePUAP flavors:
  - enveloping — the content is a base64 blob inside a `ds:Object`
  - enveloped — ePUAP "PodpisanyPlik" style, where the `ds:Reference` with
    `URI=""` covers the whole document with the embedded `ds:Signature`
    removed (via `xmldsig-filter2` or the `enveloped-signature` transform)
- **PAdES** (PDF) — `ETSI.CAdES.detached` signatures verified against the
  `/ByteRange`-covered bytes

The file type is detected from the content (`%PDF-` magic), the extension
does not matter.

## Usage

```console
$ podpis-rs doc.xml
$ podpis-rs doc.pdf
$ podpis-rs --extract out.mp4 doc.xml      # decoded signed payload
$ podpis-rs --extract out.pdf doc.pdf      # PDF with the signature cleared
```

## Limitations

- only RSA PKCS#1 v1.5 (sha1/sha256/sha512); ECDSA and RSA-PSS are not supported
- `ETSI.RFC3161` timestamp signatures (DocTimeStamp) are rejected
- no certificate chain, revocation (LTV/DSS) or signature policy validation
- one signature per document: the first PDF `/ByteRange` / first CMS
  `SignerInfo` / first `ds:Signature` is validated

## Development

```console
$ cargo build
$ cargo run -- a.xml
$ cargo clippy --all-targets -- -D warnings
$ cargo fmt --all
```

## License

MIT.
