//! scan-service — façade d'orchestration de haut niveau (release).
//!
//! Unifie le pipeline complet en un seul appel pour le service hôte
//! (`optiCombat.Service` via FFI, ou la CLI) : **scan** (réputation → moteurs →
//! corrélation) puis **protection** (mise en quarantaine automatique des
//! cibles malveillantes), la clé de quarantaine provenant de la couche
//! plateforme (DPAPI sous Windows, local ailleurs).

use std::path::{Path, PathBuf};

use correlator::FinalDecision;
use dispatcher::Dispatcher;
use engine_core::Verdict;
use platform::KeyProvider;
use quarantine::{Quarantine, QuarantineEntry};

/// Résultat d'un scan protégé : décision + éventuelle entrée de quarantaine.
#[derive(Debug)]
pub struct ScanOutcome {
    pub decision: FinalDecision,
    pub quarantined: Option<QuarantineEntry>,
}

impl ScanOutcome {
    pub fn is_malicious(&self) -> bool {
        self.decision.verdict == Verdict::Malicious
    }
}

/// Service de scan unifié, prêt à être piloté par le service hôte.
pub struct ScanService {
    dispatcher: Dispatcher,
    quarantine_dir: PathBuf,
    key: [u8; 32],
    auto_quarantine: bool,
}

impl ScanService {
    /// Construit le service ; la clé maîtresse vient de la plateforme.
    pub fn new(quarantine_dir: impl Into<PathBuf>, key_provider: &dyn KeyProvider) -> Self {
        Self {
            dispatcher: Dispatcher::new(),
            quarantine_dir: quarantine_dir.into(),
            key: key_provider.master_key(),
            auto_quarantine: true,
        }
    }

    /// Désactive la mise en quarantaine automatique (scan seul).
    pub fn without_auto_quarantine(mut self) -> Self {
        self.auto_quarantine = false;
        self
    }

    /// Scanne une cible et, si malveillante, la met en quarantaine.
    pub fn scan_and_protect(&self, path: &Path) -> std::io::Result<ScanOutcome> {
        let decision = self.dispatcher.scan_path(path)?;
        let quarantined = if self.auto_quarantine && decision.verdict == Verdict::Malicious {
            let q = Quarantine::new(self.quarantine_dir.clone(), self.key);
            match q.quarantine_file(path) {
                Ok(entry) => Some(entry),
                Err(e) => return Err(std::io::Error::other(format!("quarantaine échouée: {e}"))),
            }
        } else {
            None
        };
        Ok(ScanOutcome {
            decision,
            quarantined,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform::LocalKeyProvider;
    use std::io::Write;

    fn tmp(name: &str, data: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("oc_svc_{}_{}", std::process::id(), name));
        std::fs::File::create(&p).unwrap().write_all(data).unwrap();
        p
    }

    #[test]
    fn eicar_scanne_et_mis_en_quarantaine() {
        let dir = std::env::temp_dir().join(format!("oc_q_svc_{}", std::process::id()));
        let kp = LocalKeyProvider::from_secret(*b"test-key");
        let svc = ScanService::new(&dir, &kp);
        let eicar = tmp(
            "eicar.com",
            br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        );
        let outcome = svc.scan_and_protect(&eicar).unwrap();
        assert!(outcome.is_malicious());
        let entry = outcome.quarantined.expect("doit être mis en quarantaine");
        assert!(entry.stored_at.exists());
        let _ = std::fs::remove_file(&eicar);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fichier_propre_non_quarantaine() {
        let dir = std::env::temp_dir().join(format!("oc_q_svc2_{}", std::process::id()));
        let kp = LocalKeyProvider::from_secret(*b"test-key");
        let svc = ScanService::new(&dir, &kp);
        let clean = tmp("ok.txt", b"document parfaitement normal et anodin");
        let outcome = svc.scan_and_protect(&clean).unwrap();
        assert!(!outcome.is_malicious());
        assert!(outcome.quarantined.is_none());
        let _ = std::fs::remove_file(&clean);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
