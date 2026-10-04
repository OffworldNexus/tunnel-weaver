/// ACME certificate authority provider catalog.
///
/// Provides metadata, directory URLs, EAB requirements, rate limit quotas,
/// and credential instructions for first-class supported ACME providers.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcmeProviderInfo {
    pub id: &'static str,
    pub directory: &'static str,
    pub eab_required: bool,
    /// The CA's CAA issuer domain, if known.
    ///
    /// The authoritative responder publishes `issue`/`issuewild` CAA records
    /// for this identifier so issuance is restricted to the configured CA.
    /// `None` means we cannot name the CA (e.g. `custom`) and no CAA is served.
    pub caa_identifier: Option<&'static str>,
    pub quota: &'static str,
    pub guidance: &'static str,
}

/// The catalog of supported ACME providers.
pub const PROVIDERS: &[AcmeProviderInfo] = &[
    AcmeProviderInfo {
        id: "letsencrypt",
        directory: "https://acme-v02.api.letsencrypt.org/directory",
        eab_required: false,
        caa_identifier: Some("letsencrypt.org"),
        quota: "50 new certs / week / registered domain (renewals exempt); 300 orders / 3 h; free increase via https://isrg.formstack.com/forms/rate_limit_adjustment_request",
        guidance: "—",
    },
    AcmeProviderInfo {
        id: "letsencrypt-staging",
        directory: "https://acme-staging-v02.api.letsencrypt.org/directory",
        eab_required: false,
        caa_identifier: Some("letsencrypt.org"),
        quota: "very high, untrusted certs",
        guidance: "—",
    },
    AcmeProviderInfo {
        id: "google",
        directory: "https://dv.acme-v02.api.pki.goog/directory",
        eab_required: true,
        caa_identifier: Some("pki.goog"),
        quota: "very high, adjustable in GCP",
        guidance: "GCP project → enable Public Certificate Authority API → gcloud publicca external-account-keys create → keyId + b64MacKey. Key must be used within 7 days of creation. Docs: https://cloud.google.com/certificate-manager/docs/public-ca-tutorial",
    },
    AcmeProviderInfo {
        id: "zerossl",
        directory: "https://acme.zerossl.com/v2/DV90",
        eab_required: true,
        caa_identifier: Some("sectigo.com"),
        quota: "unlimited 90-day",
        guidance: "free account → Developer → EAB Credentials for ACME Clients. Docs: https://zerossl.com/documentation/acme/",
    },
    AcmeProviderInfo {
        id: "custom",
        directory: "any URL",
        eab_required: false,
        caa_identifier: None,
        quota: "—",
        guidance: "Pebble, step-ca, internal CAs; optional acme_root_ca_pem to trust the directory endpoint",
    },
];

/// Looks up an ACME provider by identifier.
pub fn find_provider(id: &str) -> Option<&'static AcmeProviderInfo> {
    let lower = id.to_ascii_lowercase();
    PROVIDERS.iter().find(|p| p.id.eq_ignore_ascii_case(&lower))
}

/// Returns the CAA issuer domains for the configured provider and its
/// fallbacks, deduplicated. Empty means "unknown" — serve no CAA rather than a
/// restrictive one, since an empty `issuewild` forbids wildcard issuance.
pub fn caa_identifiers(provider: &str, fallbacks: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for id in std::iter::once(provider).chain(fallbacks.iter().map(String::as_str)) {
        if let Some(domain) = find_provider(id).and_then(|p| p.caa_identifier)
            && !out.iter().any(|d| d == domain)
        {
            out.push(domain.to_string());
        }
    }
    out
}

/// Resolves the ACME directory URL for a provider ID.
pub fn resolve_directory_url(provider_id: &str, custom_directory: Option<&str>) -> Option<String> {
    if provider_id.eq_ignore_ascii_case("custom") {
        custom_directory.map(|s| s.to_string())
    } else {
        find_provider(provider_id).map(|p| p.directory.to_string())
    }
}

/// Checks whether a given provider ID mandates External Account Binding.
pub fn requires_eab(provider_id: &str) -> bool {
    find_provider(provider_id).is_some_and(|p| p.eab_required)
}

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};

/// Formats the provider catalog table for display.
pub fn format_providers_table() -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Provider")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("EAB")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Directory")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Quota (2026)")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Credentials Guidance")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
    ]);

    for p in PROVIDERS {
        let name_cell = if p.id == "letsencrypt" {
            Cell::new(format!("{} (default)", p.id))
                .add_attribute(Attribute::Bold)
                .fg(Color::Green)
        } else {
            Cell::new(p.id)
                .add_attribute(Attribute::Bold)
                .fg(Color::White)
        };

        let eab_cell = if p.eab_required {
            Cell::new("required")
                .fg(Color::Yellow)
                .add_attribute(Attribute::Bold)
        } else {
            Cell::new("no").fg(Color::DarkGrey)
        };

        table.add_row(vec![
            name_cell,
            eab_cell,
            Cell::new(p.directory).fg(Color::DarkCyan),
            Cell::new(p.quota),
            Cell::new(p.guidance),
        ]);
    }

    table.to_string()
}

/// Prints the provider catalog table to stdout.
pub fn print_providers() {
    println!("{}", format_providers_table());
}
