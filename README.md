# podpis-rs

Verifies the signature of [podpis.gov.pl](https://podpis.gov.pl) artifacts.

```console
$ podpis-rs [path/to/doc.xml]
```

Exit code is `0` when all checks pass, `1` otherwise.

## Development

```console
$ cargo build
$ cargo run -- a.xml
$ cargo clippy --all-targets -- -D warnings
$ cargo fmt --all
```

Releases are tag-driven; pushing `vX.Y.Z` (matching `Cargo.toml`) builds
binaries and publishes a GitHub release with a changelog generated from
Conventional Commits.

## License

MIT.
