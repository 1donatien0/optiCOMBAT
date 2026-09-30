//! clamd — client du démon ClamAV (protocole `clamd`).
//!
//! Implémente le sous-ensemble nécessaire au scan en flux :
//!   PING  → vérifie la disponibilité du démon (réponse "PONG")
//!   INSTREAM → envoie le contenu en chunks, reçoit "stream: <SIG> FOUND" / "OK"
//!
//! Le tramage INSTREAM (`build_instream`) et l'analyse de réponse
//! (`parse_response`) sont des fonctions pures, testées sans démon. La
//! connexion TCP réelle est best-effort : en l'absence de démon, l'appelant
//! bascule sur le moteur de signatures de secours.

use engine_core::{Detection, EngineError, EngineResult, Severity, Verdict};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Client TCP vers un démon clamd (par défaut 127.0.0.1:3310).
pub struct ClamdClient {
    addr: String,
    timeout: Duration,
}

impl ClamdClient {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn local() -> Self {
        Self::new("127.0.0.1:3310")
    }

    fn connect(&self) -> std::io::Result<TcpStream> {
        let stream = TcpStream::connect(&self.addr)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        Ok(stream)
    }

    /// Le démon répond-il ? (commande `zPING` → `PONG`).
    pub fn ping(&self) -> bool {
        let Ok(mut s) = self.connect() else {
            return false;
        };
        if s.write_all(b"zPING\0").is_err() {
            return false;
        }
        let mut buf = [0u8; 16];
        match s.read(&mut buf) {
            Ok(n) => buf[..n].windows(4).any(|w| w == b"PONG"),
            Err(_) => false,
        }
    }

    /// Scanne un buffer via INSTREAM. Renvoie un résultat normalisé.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<EngineResult, EngineError> {
        let mut s = self
            .connect()
            .map_err(|e| EngineError::Unavailable(format!("clamd injoignable: {e}")))?;
        let msg = build_instream(data);
        s.write_all(&msg)
            .map_err(|e| EngineError::Unavailable(format!("écriture clamd: {e}")))?;
        let mut resp = String::new();
        s.read_to_string(&mut resp)
            .map_err(|e| EngineError::Unavailable(format!("lecture clamd: {e}")))?;
        Ok(parse_response(&resp))
    }
}

/// Construit le message INSTREAM : `zINSTREAM\0` puis, pour chaque chunk,
/// une longueur sur 4 octets big-endian suivie des données, terminé par
/// un mot de longueur nul (`0x00000000`).
pub fn build_instream(data: &[u8]) -> Vec<u8> {
    const CHUNK: usize = 8192;
    let mut out = Vec::with_capacity(data.len() + 32);
    out.extend_from_slice(b"zINSTREAM\0");
    for chunk in data.chunks(CHUNK) {
        out.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&0u32.to_be_bytes()); // terminateur
    out
}

/// Analyse la réponse clamd : `stream: OK` ou `stream: <SIGNATURE> FOUND`.
pub fn parse_response(resp: &str) -> EngineResult {
    let line = resp.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    if line.ends_with("FOUND") {
        // Format : "stream: Eicar-Test-Signature FOUND"
        let sig = line
            .strip_prefix("stream:")
            .unwrap_or(line)
            .trim()
            .strip_suffix("FOUND")
            .unwrap_or("")
            .trim()
            .to_string();
        let severity = if sig.to_ascii_lowercase().contains("eicar") {
            Severity::Major
        } else {
            Severity::Critical
        };
        return EngineResult {
            engine: "clamav".into(),
            verdict: Verdict::Malicious,
            detections: vec![Detection {
                engine: "clamav".into(),
                name: if sig.is_empty() {
                    "clamd.Detection".into()
                } else {
                    sig.clone()
                },
                score: 100,
                severity,
                explanation: format!("Signature ClamAV (clamd) : {sig}"),
            }],
            elapsed_ms: 0,
        };
    }
    if line.contains("ERROR") {
        return EngineResult::inconclusive("clamav");
    }
    EngineResult::clean("clamav")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instream_tramage() {
        let msg = build_instream(b"AB");
        // "zINSTREAM\0" (10) + len(4) + data(2) + terminateur(4)
        assert_eq!(&msg[..10], b"zINSTREAM\0");
        assert_eq!(&msg[10..14], &[0, 0, 0, 2]); // longueur big-endian = 2
        assert_eq!(&msg[14..16], b"AB");
        assert_eq!(&msg[16..20], &[0, 0, 0, 0]); // terminateur nul
    }

    #[test]
    fn reponse_found() {
        let r = parse_response("stream: Eicar-Test-Signature FOUND\0");
        assert_eq!(r.verdict, Verdict::Malicious);
        assert_eq!(r.detections[0].name, "Eicar-Test-Signature");
    }

    #[test]
    fn reponse_ok() {
        let r = parse_response("stream: OK\0");
        assert_eq!(r.verdict, Verdict::Clean);
    }

    #[test]
    fn ping_sans_demon_est_false() {
        // Port quasi certainement fermé → pas de démon, pas de panique.
        assert!(!ClamdClient::new("127.0.0.1:1").ping());
    }
}
