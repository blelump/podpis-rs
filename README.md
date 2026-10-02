# podpis-rs

Verifies the signature of [podpis.gov.pl](https://podpis.gov.pl) artifacts.

Supports both flavors of ePUAP XAdES-BES signatures:

- enveloping — the content is a base64 blob inside a `ds:Object`
- enveloped — ePUAP "PodpisanyPlik" style, where the `ds:Reference` with
  `URI=""` covers the whole document with the embedded `ds:Signature`
  removed (via `xmldsig-filter2` or the `enveloped-signature` transform)

```console
$ podpis-rs [path/to/doc.xml]
```

## Development

```console
$ cargo build
$ cargo run -- a.xml
$ cargo clippy --all-targets -- -D warnings
$ cargo fmt --all
```

## License

MIT.
