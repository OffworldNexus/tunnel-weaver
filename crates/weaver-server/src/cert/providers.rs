/// ACME certificate authority provider catalog.
///
/// Provides metadata, directory URLs, EAB requirements, rate limit quotas,
/// and credential instructions for first-class supported ACME providers.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcmeProviderInfo {
    pub id: &'static str,
    pub directory: &'static str,
    pub eab_required: bool,
    pub quota: &'static str,
    pub guidance: &'static str,
}

/// The catalog of supported ACME providers.
pub const PROVIDERS: &[AcmeProviderInfo] = &[
    AcmeProviderInfo {
        id: "letsencrypt",
        directory: "https://acme-v02.api.letsencrypt.org/directory",
        eab_required: false,
        quota: "50 new certs / week / registered domain (renewals exempt); 300 orders / 3 h; free increase via https://isrg.formstack.com/forms/rate_limit_adjustment_request",
        guidance: "—",
    },
    AcmeProviderInfo {
        id: "letsencrypt-staging",
        directory: "https://acme-staging-v02.api.letsencrypt.org/directory",
        eab_required: false,
        quota: "very high, untrusted certs",
        guidance: "—",
    },
    AcmeProviderInfo {
        id: "google",
        directory: "https://dv.acme-v02.api.pki.goog/directory",
        eab_required: true,
        quota: "very high, adjustable in GCP",
        guidance: "GCP project → enable Public Certificate Authority API → gcloud publicca external-account-keys create → keyId + b64MacKey. Key must be used within 7 days of creation. Docs: https://cloud.google.com/certificate-manager/docs/public-ca-tutorial",
    },
    AcmeProviderInfo {
        id: "zerossl",
        directory: "https://acme.zerossl.com/v2/DV90",
        eab_required: true,
        quota: "unlimited 90-day",
        guidance: "free account → Developer → EAB Credentials for ACME Clients. Docs: https://zerossl.com/documentation/acme/",
    },
    AcmeProviderInfo {
        id: "buypass",
        directory: "https://api.buypass.com/acme/directory",
        eab_required: false,
        quota: "20 / week / domain, 180-day certs",
        guidance: "—",
    },
    AcmeProviderInfo {
        id: "custom",
        directory: "any URL",
        eab_required: false,
        quota: "—",
        guidance: "Pebble, step-ca, internal CAs; optional acme_root_ca_pem to trust the directory endpoint",
    },
];

/// Looks up an ACME provider by identifier.
pub fn find_provider(id: &str) -> Option<&'static AcmeProviderInfo> {
    let lower = id.to_ascii_lowercase();
    PROVIDERS.iter().find(|p| p.id.eq_ignore_ascii_case(&lower))
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

/// Formats the provider catalog table for display.
pub fn format_providers_table() -> String {
    let mut out = String::new();
    out.push_str("| id | directory | EAB | quota (2026) | how to get credentials |\n");
    out.push_str("| -- | -- | -- | -- | -- |\n");
    for p in PROVIDERS {
        let eab = if p.eab_required { "**yes**" } else { "no" };
        let id_label = if p.id == "letsencrypt" {
            "`letsencrypt` (default)"
        } else {
            &format!("`{}`", p.id)
        };
        let dir = if p.id == "custom" {
            p.directory.to_string()
        } else {
            format!("`{}`", p.directory)
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            id_label, dir, eab, p.quota, p.guidance
        ));
    }
    out
}

/// Prints the provider catalog table to stdout.
pub fn print_providers() {
    print!("{}", format_providers_table());
}
