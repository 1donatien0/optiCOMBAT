//! parser — chargeur de règles YARA (sous-ensemble réellement utilisé par optiCombat).
//!
//! Supporté : blocs `rule`, section `meta` (severity), section `strings`
//! (chaînes texte avec `nocase`), et conditions combinant références `$id`,
//! quantificateurs `N of them` / `any of them` / `all of them`, ensembles
//! `N of (...)` / `any of (...)` / `all of (...)` avec wildcard `$pref*`, et
//! les opérateurs `and` / `or` avec parenthèses.
//!
//! Non supporté (volontairement, absent du dépôt) : chaînes hex, regex et
//! offsets. yara-x reste le remplacement cible pour la compatibilité totale.

use engine_core::Severity;

#[derive(Debug, Clone)]
pub struct YaraString {
    pub id: String,
    pub bytes: Vec<u8>,
    pub nocase: bool,
}

#[derive(Debug, Clone)]
pub enum Count {
    Num(usize),
    Any,
    All,
}

#[derive(Debug, Clone)]
pub enum StringSet {
    Them,
    List(Vec<String>),
    Wildcard(String), // préfixe, ex. "ext" pour $ext*
}

#[derive(Debug, Clone)]
pub enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Ref(String),
    Of(Count, StringSet),
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub severity: Severity,
    pub strings: Vec<YaraString>,
    pub condition: Expr,
}

#[derive(Debug)]
pub struct ParseError(pub String);
impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "yara parse: {}", self.0)
    }
}
impl std::error::Error for ParseError {}

/// Retire les commentaires `/* */` et `//` du source.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let b = src.as_bytes();
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i] as char;
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < b.len() {
                out.push(b[i + 1] as char);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Parse toutes les règles d'un source `.yar`.
pub fn parse_rules(src: &str) -> Result<Vec<Rule>, ParseError> {
    let clean = strip_comments(src);
    let bytes = clean.as_bytes();
    let mut rules = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // Cherche le mot-clé "rule".
        let rest = &clean[i..];
        if let Some(pos) = rest.find("rule") {
            let start = i + pos;
            // Vérifie frontière de mot.
            let before_ok = start == 0 || !clean.as_bytes()[start - 1].is_ascii_alphanumeric();
            let after = start + 4;
            let after_ok = after < bytes.len() && bytes[after].is_ascii_whitespace();
            if !(before_ok && after_ok) {
                i = start + 4;
                continue;
            }
            // Nom de la règle.
            let mut j = after;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let name_start = j;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            let name = clean[name_start..j].to_string();
            // Bloc { ... } avec appariement d'accolades.
            while j < bytes.len() && bytes[j] != b'{' {
                j += 1;
            }
            if j >= bytes.len() {
                break;
            }
            let body_start = j + 1;
            let mut depth = 1;
            let mut k = body_start;
            let mut in_str = false;
            while k < bytes.len() && depth > 0 {
                let ch = bytes[k];
                if in_str {
                    // Ignore tout (y compris { }) à l'intérieur d'une chaîne.
                    if ch == b'\\' && k + 1 < bytes.len() {
                        k += 2;
                        continue;
                    }
                    if ch == b'"' {
                        in_str = false;
                    }
                    k += 1;
                    continue;
                }
                match ch {
                    b'"' => in_str = true,
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                k += 1;
            }
            let body = &clean[body_start..k - 1];
            rules.push(parse_rule_body(name, body)?);
            i = k;
        } else {
            break;
        }
    }
    if rules.is_empty() {
        return Err(ParseError("aucune règle trouvée".into()));
    }
    Ok(rules)
}

fn section<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}:");
    let start = body.find(&key)? + key.len();
    // La section va jusqu'à la prochaine section connue.
    let mut end = body.len();
    for next in ["meta:", "strings:", "condition:"] {
        if let Some(p) = body[start..].find(next) {
            end = end.min(start + p);
        }
    }
    Some(&body[start..end])
}

fn parse_rule_body(name: String, body: &str) -> Result<Rule, ParseError> {
    let severity = section(body, "meta")
        .and_then(parse_severity)
        .unwrap_or(Severity::Major);
    let strings = match section(body, "strings") {
        Some(s) => parse_strings(s)?,
        None => Vec::new(),
    };
    let cond_src = section(body, "condition")
        .ok_or_else(|| ParseError(format!("règle {name}: condition manquante")))?;
    let condition = parse_condition(cond_src)?;
    Ok(Rule {
        name,
        severity,
        strings,
        condition,
    })
}

fn parse_severity(meta: &str) -> Option<Severity> {
    let pos = meta.find("severity")? + "severity".len();
    let rest = &meta[pos..];
    let q1 = rest.find('"')? + 1;
    let q2 = rest[q1..].find('"')? + q1;
    let val = rest[q1..q2].to_ascii_lowercase();
    Some(match val.as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::Major,
        "medium" => Severity::Minor,
        "low" => Severity::Informational,
        "test" => Severity::Major,
        _ => Severity::Major,
    })
}

fn parse_strings(s: &str) -> Result<Vec<YaraString>, ParseError> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'$' {
            let id_start = i + 1;
            let mut j = id_start;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                j += 1;
            }
            let id = s[id_start..j].to_string();
            // Cherche '=' puis '"'.
            while j < b.len() && b[j] != b'"' && b[j] != b'\n' {
                j += 1;
            }
            if j >= b.len() || b[j] == b'\n' {
                i = j;
                continue;
            }
            // Lit la chaîne quotée avec échappements.
            let mut bytes = Vec::new();
            j += 1; // après le guillemet ouvrant
            while j < b.len() && b[j] != b'"' {
                if b[j] == b'\\' && j + 1 < b.len() {
                    let esc = b[j + 1];
                    bytes.push(match esc {
                        b'n' => b'\n',
                        b't' => b'\t',
                        b'r' => b'\r',
                        other => other, // \\ \" etc. → caractère littéral
                    });
                    j += 2;
                    continue;
                }
                bytes.push(b[j]);
                j += 1;
            }
            if j < b.len() {
                j += 1; // consomme le guillemet fermant s'il est présent
            }
            j = j.min(b.len());
            // Modificateur nocase jusqu'à fin de ligne.
            let mut line_end = j;
            while line_end < b.len() && b[line_end] != b'\n' {
                line_end += 1;
            }
            let nocase = s[j..line_end].to_ascii_lowercase().contains("nocase");
            out.push(YaraString { id, bytes, nocase });
            i = line_end;
        } else {
            i += 1;
        }
    }
    Ok(out)
}

// ---- Condition : tokenizer + parseur à descente récursive ----

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    LParen,
    RParen,
    Comma,
    Id(String, bool), // (nom, wildcard)
    Num(usize),
    Of,
    Them,
    Any,
    All,
    And,
    Or,
}

fn tokenize(src: &str) -> Result<Vec<Tok>, ParseError> {
    let b = src.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        match c {
            b'(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            b',' => {
                toks.push(Tok::Comma);
                i += 1;
            }
            b'$' => {
                let start = i + 1;
                let mut j = start;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                let mut wildcard = false;
                let name = src[start..j].to_string();
                if j < b.len() && b[j] == b'*' {
                    wildcard = true;
                    j += 1;
                }
                toks.push(Tok::Id(name, wildcard));
                i = j;
            }
            _ if c.is_ascii_digit() => {
                let start = i;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                let n: usize = src[start..i]
                    .parse()
                    .map_err(|_| ParseError("nombre invalide".into()))?;
                toks.push(Tok::Num(n));
            }
            _ if c.is_ascii_alphabetic() => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                let w = src[start..i].to_ascii_lowercase();
                toks.push(match w.as_str() {
                    "of" => Tok::Of,
                    "them" => Tok::Them,
                    "any" => Tok::Any,
                    "all" => Tok::All,
                    "and" => Tok::And,
                    "or" => Tok::Or,
                    other => return Err(ParseError(format!("mot-clé inconnu: {other}"))),
                });
            }
            _ => return Err(ParseError(format!("caractère inattendu: {}", c as char))),
        }
    }
    Ok(toks)
}

struct Cursor {
    toks: Vec<Tok>,
    pos: usize,
}
impl Cursor {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
}

pub fn parse_condition(src: &str) -> Result<Expr, ParseError> {
    let toks = tokenize(src)?;
    if toks.is_empty() {
        return Err(ParseError("condition vide".into()));
    }
    let mut cur = Cursor { toks, pos: 0 };
    let e = parse_or(&mut cur)?;
    Ok(e)
}

fn parse_or(c: &mut Cursor) -> Result<Expr, ParseError> {
    let mut left = parse_and(c)?;
    while c.eat(&Tok::Or) {
        let right = parse_and(c)?;
        left = Expr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(c: &mut Cursor) -> Result<Expr, ParseError> {
    let mut left = parse_primary(c)?;
    while c.eat(&Tok::And) {
        let right = parse_primary(c)?;
        left = Expr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_primary(c: &mut Cursor) -> Result<Expr, ParseError> {
    match c.peek().cloned() {
        Some(Tok::LParen) => {
            c.next();
            let e = parse_or(c)?;
            if !c.eat(&Tok::RParen) {
                return Err(ParseError("parenthèse fermante attendue".into()));
            }
            Ok(e)
        }
        Some(Tok::Num(n)) => {
            c.next();
            parse_of(c, Count::Num(n))
        }
        Some(Tok::Any) => {
            c.next();
            parse_of(c, Count::Any)
        }
        Some(Tok::All) => {
            c.next();
            parse_of(c, Count::All)
        }
        Some(Tok::Id(name, _)) => {
            c.next();
            Ok(Expr::Ref(name))
        }
        other => Err(ParseError(format!("primaire inattendu: {other:?}"))),
    }
}

fn parse_of(c: &mut Cursor, count: Count) -> Result<Expr, ParseError> {
    if !c.eat(&Tok::Of) {
        return Err(ParseError("'of' attendu".into()));
    }
    match c.next() {
        Some(Tok::Them) => Ok(Expr::Of(count, StringSet::Them)),
        Some(Tok::LParen) => {
            // Liste d'identifiants, éventuellement un seul wildcard.
            let mut ids = Vec::new();
            let mut wildcard: Option<String> = None;
            loop {
                match c.next() {
                    Some(Tok::Id(name, true)) => wildcard = Some(name),
                    Some(Tok::Id(name, false)) => ids.push(name),
                    Some(Tok::RParen) => break,
                    Some(Tok::Comma) => continue,
                    other => return Err(ParseError(format!("set invalide: {other:?}"))),
                }
                if c.eat(&Tok::RParen) {
                    break;
                }
            }
            if let Some(pref) = wildcard {
                Ok(Expr::Of(count, StringSet::Wildcard(pref)))
            } else {
                Ok(Expr::Of(count, StringSet::List(ids)))
            }
        }
        other => Err(ParseError(format!("set attendu après of: {other:?}"))),
    }
}
