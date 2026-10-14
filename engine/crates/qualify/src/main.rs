//! qualify — harness de qualification détection (panel EICAR + échantillons).
//!
//! Usage :
//!   oc-qualify --report report.json --manifest qualification/manifest.json
//!   oc-qualify --manifest manifest.json --min-malicious-rate 0.85 --max-fpr-rate 0.01
//!
//! Code de sortie : 0 si tous les échantillons et seuils globaux sont conformes.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use dispatcher::Dispatcher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct SampleExpectation {
    path: String,
    expect: String,
    label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct QualifyManifest {
    samples: Vec<SampleExpectation>,
}

#[derive(Debug, Serialize)]
struct SampleReport {
    path: String,
    label: Option<String>,
    verdict: String,
    expect: String,
    pass: bool,
    detections: Vec<String>,
}

#[derive(Debug, Serialize)]
struct QualifyMetrics {
    malicious_expected: usize,
    malicious_detected: usize,
    detection_rate: f64,
    benign_expected: usize,
    false_positives: usize,
    false_positive_rate: f64,
}

#[derive(Debug, Serialize)]
struct QualifyThresholds {
    min_malicious_rate: f64,
    max_fpr_rate: f64,
    met: bool,
}

#[derive(Debug, Serialize)]
struct QualifyReport {
    total: usize,
    passed: usize,
    failed: usize,
    false_positives: usize,
    missed: usize,
    metrics: QualifyMetrics,
    thresholds: Option<QualifyThresholds>,
    samples: Vec<SampleReport>,
}

struct RunOptions {
    min_malicious_rate: Option<f64>,
    max_fpr_rate: Option<f64>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!(
            "usage: oc-qualify [--report path.json] [--manifest path.json] \\
       [--min-malicious-rate 0.85] [--max-fpr-rate 0.01] [files...]"
        );
        return ExitCode::from(2);
    }

    let mut report_path: Option<PathBuf> = None;
    let mut manifest_path: Option<PathBuf> = None;
    let mut files: Vec<PathBuf> = Vec::new();
    let mut options = RunOptions {
        min_malicious_rate: None,
        max_fpr_rate: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--report" if i + 1 < args.len() => {
                report_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--manifest" if i + 1 < args.len() => {
                manifest_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--min-malicious-rate" if i + 1 < args.len() => {
                options.min_malicious_rate = args[i + 1].parse().ok();
                i += 2;
            }
            "--max-fpr-rate" if i + 1 < args.len() => {
                options.max_fpr_rate = args[i + 1].parse().ok();
                i += 2;
            }
            _ => {
                files.push(PathBuf::from(&args[i]));
                i += 1;
            }
        }
    }

    let expectations = if let Some(m) = manifest_path {
        load_manifest(&m).unwrap_or_else(|e| {
            eprintln!("manifest: {e}");
            std::process::exit(2);
        })
    } else {
        files
            .iter()
            .map(|p| SampleExpectation {
                path: p.display().to_string(),
                expect: "any".into(),
                label: None,
            })
            .collect()
    };

    let report = run_panel(&expectations, &options);
    let json = serde_json::to_string_pretty(&report).unwrap();
    if let Some(out) = report_path {
        let _ = fs::write(out, &json);
    }
    println!("{json}");

    let thresholds_ok = report.thresholds.as_ref().is_none_or(|t| t.met);
    if report.failed > 0 || !thresholds_ok {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

fn load_manifest(path: &Path) -> Result<Vec<SampleExpectation>, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let m: QualifyManifest = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    Ok(m.samples)
}

fn run_panel(expectations: &[SampleExpectation], options: &RunOptions) -> QualifyReport {
    let dispatcher = Dispatcher::new();
    let mut samples = Vec::new();
    let mut passed = 0usize;
    let mut false_positives = 0usize;
    let mut missed = 0usize;
    let mut malicious_expected = 0usize;
    let mut malicious_detected = 0usize;
    let mut benign_expected = 0usize;

    for exp in expectations {
        if exp.expect == "malicious" {
            malicious_expected += 1;
        }
        if exp.expect == "clean" {
            benign_expected += 1;
        }

        let path = Path::new(&exp.path);
        let (verdict, detections) = match dispatcher.scan_path(path) {
            Ok(d) => (
                format!("{:?}", d.verdict),
                d.reasons
                    .iter()
                    .map(|r| format!("{}:{}", r.engine, r.name))
                    .collect(),
            ),
            Err(e) => ("Error".into(), vec![e.to_string()]),
        };

        let malicious = matches_verdict(&verdict, "malicious");
        let clean = matches_verdict(&verdict, "clean");
        if exp.expect == "malicious" && malicious {
            malicious_detected += 1;
        }

        let pass = match exp.expect.as_str() {
            "malicious" => malicious,
            "clean" => clean,
            "any" => true,
            other => verdict.eq_ignore_ascii_case(other),
        };

        if pass {
            passed += 1;
        } else if exp.expect == "malicious" && !malicious {
            missed += 1;
        } else if exp.expect == "clean" && !clean {
            false_positives += 1;
        }

        samples.push(SampleReport {
            path: exp.path.clone(),
            label: exp.label.clone(),
            verdict: verdict.clone(),
            expect: exp.expect.clone(),
            pass,
            detections,
        });
    }

    let detection_rate = if malicious_expected == 0 {
        1.0
    } else {
        malicious_detected as f64 / malicious_expected as f64
    };
    let false_positive_rate = if benign_expected == 0 {
        0.0
    } else {
        false_positives as f64 / benign_expected as f64
    };

    let thresholds = match (options.min_malicious_rate, options.max_fpr_rate) {
        (Some(min_rate), Some(max_fpr)) => Some(QualifyThresholds {
            min_malicious_rate: min_rate,
            max_fpr_rate: max_fpr,
            met: detection_rate >= min_rate && false_positive_rate <= max_fpr,
        }),
        _ => None,
    };

    QualifyReport {
        total: expectations.len(),
        passed,
        failed: expectations.len().saturating_sub(passed),
        false_positives,
        missed,
        metrics: QualifyMetrics {
            malicious_expected,
            malicious_detected,
            detection_rate,
            benign_expected,
            false_positives,
            false_positive_rate,
        },
        thresholds,
        samples,
    }
}

fn matches_verdict(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
        || (expected == "malicious" && actual.contains("Malicious"))
        || (expected == "clean" && (actual.contains("Clean") || actual.contains("Inconclusive")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eicar_in_manifest_detected() {
        let eicar = std::env::temp_dir().join(format!("eicar_{}.com", std::process::id()));
        let payload = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        fs::write(&eicar, payload).unwrap();
        let report = run_panel(
            &[SampleExpectation {
                path: eicar.display().to_string(),
                expect: "malicious".into(),
                label: Some("EICAR".into()),
            }],
            &RunOptions {
                min_malicious_rate: None,
                max_fpr_rate: None,
            },
        );
        let _ = fs::remove_file(&eicar);
        assert!(report.passed >= 1, "{report:?}");
        assert_eq!(report.metrics.detection_rate, 1.0);
    }

    #[test]
    fn thresholds_enforced() {
        let benign = std::env::temp_dir().join(format!("benign_{}.txt", std::process::id()));
        fs::write(&benign, b"hello world").unwrap();
        let report = run_panel(
            &[SampleExpectation {
                path: benign.display().to_string(),
                expect: "clean".into(),
                label: None,
            }],
            &RunOptions {
                min_malicious_rate: Some(1.0),
                max_fpr_rate: Some(0.0),
            },
        );
        let _ = fs::remove_file(&benign);
        let t = report.thresholds.expect("thresholds");
        assert!(t.met);
    }
}
