//! Flat-hostname naming rules and derivation.
//!
//! A tunnel is reachable at `<person>-<machine>-<service>.<root>`: a single
//! lowercased label directly under the zone apex. Because the wildcard
//! certificate covers exactly one label (`*.<root>` does not match
//! `a.b.<root>`), the flat form is a hard invariant, not a style choice.
//!
//! Person and machine names cannot contain a dash, so the label splits at its
//! first two dashes: person, then machine, then the rest is the service. The
//! service may contain dashes. All three are validated at creation time and the
//! resulting hostname is a database uniqueness constraint.
//!
//! This module holds the pure rules; the `Store` applies them and recomputes
//! materialized `domains.name` rows when an entity is renamed.

/// Maximum length of a person or machine name.
pub const PERSON_MACHINE_MAX: usize = 15;

/// Maximum length of a service name.
pub const SERVICE_MAX: usize = 31;

/// Validates a person or machine name: `^[a-z0-9]{1,15}$`.
///
/// Dashes are excluded on purpose — they are the separator in the flat label.
pub fn is_valid_person_or_machine(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= PERSON_MACHINE_MAX
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Validates a service name: `^(?=.{1,31}$)[a-z0-9]+(?:-[a-z0-9]+)*$`.
///
/// Dashes are allowed *between* alphanumeric runs but not leading, trailing, or
/// doubled; that keeps the flat label unambiguous when split on the first two
/// dashes.
pub fn is_valid_service(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > SERVICE_MAX {
        return false;
    }
    let mut prev_dash = false;
    for &b in bytes {
        match b {
            b'a'..=b'z' | b'0'..=b'9' => prev_dash = false,
            b'-' if prev_dash => return false,
            b'-' => prev_dash = true,
            _ => return false,
        }
    }
    // Reject a leading or trailing dash: `prev_dash` is still true at the end
    // if the last byte was a dash, and a leading dash was recorded before any
    // alphanumeric run.
    !prev_dash && !name.starts_with('-')
}

/// Lowercases a domain and strips any trailing dot, for comparison.
pub fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Builds the materialized flat hostname for a service, lowercased.
pub fn flat_hostname(person: &str, machine: &str, service: &str, root: &str) -> String {
    format!(
        "{}-{}-{}.{}",
        person.to_ascii_lowercase(),
        machine.to_ascii_lowercase(),
        service.to_ascii_lowercase(),
        root.to_ascii_lowercase()
    )
}

/// Folds one character to the ASCII letter a slug should carry, or `None` to
/// drop it.
///
/// A deliberately small table rather than a transliteration dependency: the
/// only thing that matters is that `Rémy` becomes `remy`, not `rmy`. Input is
/// expected to be already lowercased.
fn fold_ascii(c: char) -> Option<char> {
    match c {
        'a'..='z' | '0'..='9' => Some(c),
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => Some('a'),
        'ç' | 'ć' | 'č' => Some('c'),
        'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' => Some('e'),
        'ì' | 'í' | 'î' | 'ï' | 'ī' | 'į' => Some('i'),
        'ñ' | 'ń' | 'ň' => Some('n'),
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ő' => Some('o'),
        'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ů' | 'ű' | 'ų' => Some('u'),
        'ý' | 'ÿ' => Some('y'),
        'ß' => Some('s'),
        'æ' => Some('a'),
        'œ' => Some('o'),
        _ => None,
    }
}

/// Normalises arbitrary text into the `^[a-z0-9]{1,15}$` shape a person or
/// machine name must take.
///
/// Lowercases, folds common accented Latin letters to ASCII, drops everything
/// else (dashes, dots, spaces, punctuation) and truncates to the label limit.
/// Input that yields nothing falls back to `fallback`.
pub fn slugify(raw: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(PERSON_MACHINE_MAX);
    for c in raw.to_lowercase().chars() {
        if let Some(folded) = fold_ascii(c) {
            out.push(folded);
            if out.len() == PERSON_MACHINE_MAX {
                break;
            }
        }
    }
    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

/// The proposed person slug for an account display name.
pub fn slugify_person(display_name: &str) -> String {
    slugify(display_name, "person")
}

/// The proposed machine name for a raw hostname, e.g.
/// `Rémys-MacBook-Pro.local` → `remysmacbookpro`.
pub fn slugify_machine(raw_hostname: &str) -> String {
    slugify(raw_hostname, "machine")
}

/// Returns `base`, or the first `<truncated base><n>` (with `n >= 2`) that
/// `taken` reports as free.
///
/// The suffix is a bare digit appended *after* truncation, so every candidate is
/// still `^[a-z0-9]{1,15}$` and — crucially — contains no dash, which would
/// break the flat label's split on the first two dashes.
pub fn uniquify(base: &str, mut taken: impl FnMut(&str) -> bool) -> String {
    if !taken(base) {
        return base.to_string();
    }
    let mut n: u32 = 2;
    loop {
        let suffix = n.to_string();
        let keep = PERSON_MACHINE_MAX.saturating_sub(suffix.len());
        let mut candidate: String = base.chars().take(keep).collect();
        candidate.push_str(&suffix);
        if !taken(&candidate) {
            return candidate;
        }
        n = n.saturating_add(1);
    }
}

/// True if `name` is a label the authoritative responder owns and no entity
/// may shadow: the apex itself, or `_acme-challenge.<root>`.
///
/// A derived flat name can never collide (underscores and dots are invalid in
/// person/machine/service), but parent-zone records can, so `setup` checks this
/// too.
pub fn is_reserved_label(name: &str, root: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let root = root.to_ascii_lowercase();
    name == root || name == format!("_acme-challenge.{root}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn person_and_machine_rules() {
        assert!(is_valid_person_or_machine("poc"));
        assert!(is_valid_person_or_machine("a1"));
        assert!(is_valid_person_or_machine(&"a".repeat(15)));
        assert!(!is_valid_person_or_machine(""));
        assert!(!is_valid_person_or_machine("a".repeat(16).as_str()));
        assert!(!is_valid_person_or_machine("has-dash"));
        assert!(!is_valid_person_or_machine("Upper"));
        assert!(!is_valid_person_or_machine("under_score"));
    }

    #[test]
    fn service_rules() {
        assert!(is_valid_service("web"));
        assert!(is_valid_service("my-app"));
        assert!(is_valid_service("a-b-c-1"));
        assert!(is_valid_service(&"a".repeat(31)));
        assert!(!is_valid_service(""));
        assert!(!is_valid_service(&"a".repeat(32)));
        assert!(!is_valid_service("-web"));
        assert!(!is_valid_service("web-"));
        assert!(!is_valid_service("a--b"));
        assert!(!is_valid_service("a.b"));
        assert!(!is_valid_service("Web"));
    }

    #[test]
    fn flat_hostname_shape() {
        assert_eq!(
            flat_hostname("Poc", "Laptop", "My-Web", "Example.COM"),
            "poc-laptop-my-web.example.com"
        );
    }

    #[test]
    fn slugify_person_and_machine() {
        assert_eq!(slugify_person("Rémy Sanchez"), "remysanchez");
        assert_eq!(
            slugify_machine("Rémys-MacBook-Pro.local"),
            "remysmacbookpro"
        );
        assert_eq!(slugify_person("Éléonore"), "eleonore");
        assert_eq!(slugify_person(""), "person");
        assert_eq!(slugify_machine("---"), "machine");
        assert_eq!(slugify_person(&"x".repeat(40)), "x".repeat(15));
        // Whatever goes in, a valid name comes out.
        for raw in ["Rémy", "", "---", "ù", "日本語", "a.b-c d/e"] {
            assert!(is_valid_person_or_machine(&slugify_person(raw)));
            assert!(is_valid_person_or_machine(&slugify_machine(raw)));
        }
    }

    #[test]
    fn uniquify_appends_digits_without_dashes() {
        let taken = |n: &str| n == "laptop" || n == "laptop2";
        assert_eq!(uniquify("web", taken), "web");
        assert_eq!(uniquify("laptop", taken), "laptop3");

        // A full-length base truncates to make room for the suffix, and the
        // result stays within the 15-character limit and dash-free.
        let long = "a".repeat(15);
        let only_long = |n: &str| n == long;
        let next = uniquify(&long, only_long);
        assert_eq!(next, format!("{}2", "a".repeat(14)));
        assert!(is_valid_person_or_machine(&next));
    }

    #[test]
    fn reserved_labels() {
        assert!(is_reserved_label("example.com", "example.com"));
        assert!(is_reserved_label(
            "_acme-challenge.example.com",
            "example.com"
        ));
        assert!(!is_reserved_label(
            "poc-laptop-web.example.com",
            "example.com"
        ));
    }
}
