use std::path::PathBuf;
use std::process::ExitCode;

use evidence_bundle::verify_bundle;

fn usage() -> ExitCode {
    eprintln!("usage: verify <bundle-dir> [--json]");
    eprintln!("       verifier for sealed evidence bundles (seal + notary proof)");
    eprintln!("exit:  0 verified · 2 bundle rejected · 3 usage error");
    ExitCode::from(3)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    if positional.len() != 1 {
        return usage();
    }
    let dir: PathBuf = PathBuf::from(positional[0]);

    match verify_bundle(&dir) {
        Ok(report) => {
            if json {
                let obj = serde_json::json!({
                    "ok": true,
                    "case_id": report.case_id,
                    "bundle_hash": report.bundle_hash,
                    "files_verified": report.files_verified,
                    "gaps": report.gaps,
                    "provenance": report.provenance,
                    "notary_records": report.notary_records,
                });
                println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
            } else {
                println!("verified {}", report.case_id);
                println!("hash     {}", report.bundle_hash);
                println!("files    {} verified", report.files_verified);
                println!("gaps     {}", report.gaps);
                if let Some(kind) = report.provenance {
                    match report.notary_records {
                        Some(n) => println!("provenance {kind} ({n} signed records verified)"),
                        None => println!("provenance {kind} (proof files present)"),
                    }
                }
            }
            ExitCode::from(0)
        }
        Err(e) => {
            if json {
                let obj = serde_json::json!({ "ok": false, "error": e.message, "exit_code": e.exit_code });
                println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
            } else {
                eprintln!("{}", e.message);
            }
            ExitCode::from(e.exit_code)
        }
    }
}
