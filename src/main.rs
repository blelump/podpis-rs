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
            println!(
                "Signed content      : {:?}",
                String::from_utf8_lossy(&v.content)
            );

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
