# 9. Transactional email: one provider abstraction, typed templates

Date: 2026-10-06

## Status

Accepted. Implements OFF-193.

## Context

The relay must send transactional email (account verification, password reset,
security notices) without operating outbound SMTP itself. OFF-160/161/164
settled the shape: use a provider, never raw SMTP; let the provider own
bounces, suppression, retries, and delivery observability; make email opt-in;
and support a fixed provider set behind one small abstraction. OFF-193 builds
that abstraction and proves it end to end with a development "joke" template.
The six branded account emails are relocated and wired by OFF-194/OFF-191.

## Decision

### Provider abstraction

One `Mailer` trait (`compose`/`plain`/`send`) over two transports:

- **HTTP**, shaped from a single catalog (`email/providers.rs`) that mirrors
  `cert/providers.rs`. Endpoint, auth scheme, and body shape are data; only the
  request body differs per provider and that lives in one match.
- **SMTP**, built on `lettre` for MIME/`Message` construction and the SMTP
  conversation.

`compose` takes a `&dyn EmailTemplate` and a `Mailbox` (not `impl Trait`)
purely so `Arc<dyn Mailer>` stays object-safe across `setup`, `configure`, and
the hidden `send-a-joke` verb. Provider differences never leak into the
message model: callers build one normalised `Email`, and the transport stamps
the configured `From`.

The HTTP client is `hyper` + `hyper-rustls` with the platform verifier and
redirects disabled, reusing crates already in the dependency graph rather than
adding `reqwest`. Every send is awaited under a 10 s timeout.

AWS SES (SigV4) and Azure ACS (HMAC SAS) are catalogued — so the catalog stays
the whole OFF-164 answer and validation accepts them — but their bespoke
signing transports are a fast follow; `mailer_from_config` returns a clear
`Config` error for them.

### Secret storage and redaction

Credentials live in the existing config singleton inside SQLite, the same
trust model as the ACME EAB material and certificate private keys: the DB file
is 0600. `EmailConfig` has a hand-written `Debug` that prints `api_key` and
`secret` as `[redacted]`, and every transport error string is scrubbed of the
mailer's secrets before it becomes a `MailerError`. `status` and `doctor` never
print credentials.

Interactive `setup` gathers credentials before the `sudo` re-exec — where the
secrets would otherwise appear in `argv` and hence in `ps` — and hands them to
the elevated child through a **mode-0600 staging file whose path alone crosses
the boundary**. The child reads and unlinks it. Headless `configure`/`setup`
collect credentials from flags or `--email-api-key-file`, never from ambient
`argv` forwarding.

### Provider proof is a mandatory OTP

Opting into email is not done until the operator proves the provider by
receiving a short numeric code. The challenge is generated from the process
CSPRNG, hashed (SHA-256) before persistence, and carries a TTL and an attempt
cap. Interactive `setup` verifies in memory before elevation; headless
`configure` is a deliberate two-step — the first run sends the code and fails
with "OTP was sent", the second passes `--email-otp CODE` (or
`WEAVER_EMAIL_OTP`). A wrong, expired, or undeliverable code blocks setup; there
is no skip.

### Typed templates, filled then compiled

Known emails are typed `EmailTemplate`s with owned context, never a stringly
dict. Each ships one MJML source and one authored plain-text twin. Askama fills
the typed context — HTML-escaping every value, including attributes — and
renders the shared partials into in-memory strings; a `MemoryIncludeLoader`
then serves those rendered partials to `mrml`, so compilation never touches the
filesystem at runtime. This is the inverse of the brand README's "compile MJML
first, then substitute": filling first and compiling once satisfies the same
rules (escape everything, reject missing values, never inject untrusted markup)
in a single pass. `mrml` runs with strict validation and CSS inlining, per send
and uncached. Every templated send is `multipart/alternative`; the setup OTP is
plain text.

### Localisation (deferred)

Copy is **English only**. The project has no i18n yet, so the ticket's
64-locale plan is deliberately not implemented: shipping sixty-four tables that
nothing consumes would be speculative. The typed `EmailTemplate` context keeps
the seam open — a later ticket can introduce per-locale tables behind the same
`render` call without touching callers or the transports.

## Consequences

- Adding an HTTP provider is one catalog row plus, at most, a body-shape branch;
  a request-shaping test pins its method, URL, auth header, content type, and
  exact body against a fixture message.
- Provider differences that are not expressible as catalog data (SES/Azure
  signing, Loops' template-only constraint) are isolated and explicit; Loops is
  accepted only with a template id.
- No bounce/suppression/retry/queue/webhook machinery exists: an accepted send
  is a tracing event and nothing is persisted. This is deliberate (OFF-161) and
  is revisited only if a provider forces it.
- `deny.toml` allows `MPL-2.0` (pulled by `mrml`'s `css-inline` via `cssparser`
  and `selectors`) and `0BSD` (`quoted_printable` through `lettre`, and the
  `mailparse` dev-dependency). Both are OSI-approved.
