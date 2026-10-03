use std::process::ExitCode;

use clap::Parser;
use podpis_rs::validate;

#[derive(Parser, Debug)]
#[command(
    name = "podpis-rs",
    version,
    about = "Validate XAdES-BES enveloping XML signatures"
)]
struct Args {
    #[arg(default_value = "a.xml")]
    path: std::path::PathBuf,
    #[arg(long, short, value_name = "FILE")]
    extract: Option<std::path::PathBuf>,
}

fn describe_content(content: &[u8]) -> String {
    match std::str::from_utf8(content) {
        Ok(text) => {
            let trimmed = text.trim();
            let preview: String = trimmed.chars().take(120).collect();
            if trimmed.chars().count() > 120 {
                format!("text, {} bytes: {preview}…", content.len())
            } else {
                format!("text, {} bytes: {preview}", content.len())
            }
        }
        Err(_) => format!("binary, {} bytes (use --extract to save)", content.len()),
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match validate(&args.path) {
        Ok(v) => {
            println!("File: {}\n", args.path.display());
            for check in &v.checks {
                if check.ok {
                    println!("[PASS] {}", check.name);
                } else {
                    println!("[FAIL] {}", check.name);
                    if !check.expected.is_empty() {
                        println!("         expected: {}", check.expected);
                    }
                    if !check.computed.is_empty() {
                        println!("         computed: {}", check.computed);
                    }
                }
            }

            println!("\nCertificate subject : {}", v.subject);
            println!("Certificate issuer  : {}", v.issuer);
            println!("Certificate validity: {} -> {}", v.not_before, v.not_after);
            if let Some(t) = &v.signing_time {
                println!("Signing time        : {t}");
            }
            println!("Signed content      : {}", describe_content(&v.content));

            if let Some(out) = &args.extract {
                if let Err(err) = std::fs::write(out, &v.content) {
                    eprintln!("error: writing {}: {err:#}", out.display());
                    return ExitCode::FAILURE;
                }
                println!("Extracted content  -> {}", out.display());
            }

            if v.all_passed() {
                println!("\n=== ALL SIGNATURE CHECKS PASSED ===");
                ExitCode::SUCCESS
            } else {
                println!("\n=== VALIDATION FAILED ===");
                ExitCode::FAILURE
            }
        }
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
