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

/// Faux démon clamd (tests de cette crate) : répond PONG et une réponse INSTREAM fixe.
#[cfg(test)]
pub(crate) mod fake {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Lance un serveur qui traite `connections` connexions puis s'arrête.
    /// Renvoie l'adresse et le fil d'exécution.
    pub fn spawn(
        connections: usize,
        scan_reply: &'static str,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            for _ in 0..connections {
                let Ok((mut s, _)) = listener.accept() else {
                    return;
                };
                let mut cmd = [0u8; 10];
                if s.read_exact(&mut cmd[..6]).is_err() {
                    continue;
                }
                if &cmd[..6] == b"zPING\0" {
                    let _ = s.write_all(b"PONG\0");
                    continue;
                }
                // zINSTREAM\0 : lire le reste de la commande puis les chunks.
                let _ = s.read_exact(&mut cmd[6..10]);
                loop {
                    let mut len = [0u8; 4];
                    if s.read_exact(&mut len).is_err() {
                        break;
                    }
                    let n = u32::from_be_bytes(len) as usize;
                    if n == 0 {
                        break;
                    }
                    let mut buf = vec![0u8; n];
                    if s.read_exact(&mut buf).is_err() {
                        break;
                    }
                }
                let _ = s.write_all(scan_reply.as_bytes());
            }
        });
        (addr, handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_et_scan_via_un_demon_local() {
        let (addr, h) = fake::spawn(3, "stream: Win.Test.Fake FOUND\0");
        let c = ClamdClient::new(addr.clone());
        assert!(c.ping());
        let r = c.scan_bytes(&vec![7u8; 20_000]).unwrap(); // plusieurs chunks
        assert_eq!(r.verdict, Verdict::Malicious);
        assert_eq!(r.detections[0].name, "Win.Test.Fake");
        assert_eq!(r.detections[0].severity, Severity::Critical);
        let r = c.scan_bytes(b"x").unwrap();
        assert_eq!(r.verdict, Verdict::Malicious);
        h.join().unwrap();
        // Démon arrêté : ni PONG ni scan.
        assert!(!c.ping());
        assert!(matches!(
            c.scan_bytes(b"x"),
            Err(EngineError::Unavailable(_))
        ));
    }

    #[test]
    fn reponses_ok_erreur_et_eicar() {
        assert_eq!(parse_response("stream: OK\0").verdict, Verdict::Clean);
        assert_eq!(
            parse_response("INSTREAM size limit exceeded. ERROR").verdict,
            Verdict::Inconclusive
        );
        let e = parse_response("stream: Eicar-Test-Signature FOUND");
        assert_eq!(e.detections[0].severity, Severity::Major);
        let anon = parse_response("FOUND");
        assert_eq!(anon.detections[0].name, "clamd.Detection");
        assert_eq!(ClamdClient::local().addr, "127.0.0.1:3310");
    }

    #[test]
    fn instream_vide_et_multi_chunks() {
        let empty = build_instream(b"");
        assert_eq!(empty.len(), 14);
        let big = build_instream(&[1u8; 8193]);
        // en-tête + (4 + 8192) + (4 + 1) + terminateur
        assert_eq!(big.len(), 10 + 4 + 8192 + 4 + 1 + 4);
    }

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
