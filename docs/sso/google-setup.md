# Google — registering the app for the SSO preset

Steps an operator has to follow to enable the Google identity provider
(WVR-173). Values appear as `<placeholders>`.

Google is a *direct* provider: the relay runs the OIDC authorization-code + PKCE
flow itself, with `openid email profile`. Those scopes are non-sensitive, so no
Google verification review is needed — only the consent screen's branding.

## 1. A project and the consent screen

1. Create or select a **project** in the [Google Cloud console](https://console.cloud.google.com/).
2. Open **Google Auth Platform** (formerly *OAuth consent screen*) and fill in
   **Branding**: app name, support email, logo, authorized domains.
3. Set **Audience**/**User type**:
   - **External** — any Google account;
   - **Internal** — only accounts in your Workspace organization.

## 2. An OAuth client

**Google Auth Platform → Clients → Create client**, application type **Web
application**:

- **Authorized redirect URIs** — matching the relay **verbatim**:
  - development: `http://localhost:43871/api/account/sso/google/callback`
  - production: `https://<admin-domain>/api/account/sso/google/callback`

Copy the **Client ID** and **Client secret**.

## 3. Publishing status (read this before going live)

An **External** app whose publishing status is **Testing** issues refresh tokens
that expire after **7 days**. That is fine for a development relay and fatal for
production: the relay's hourly housekeeping will see an `invalid_grant` and end
the sessions it was keeping alive.

**Publish the app to Production** before relying on it. An **Internal**
(Workspace-only) app has no such limit.

## 4. MFA (`amr`) — a hard prerequisite for `Strong`

Google reports the authentication methods it used in `amr`, but only when the
claim is requested **and** enabled for the project. The relay always requests it:

```json
{"id_token":{"amr":{"essential":true}}}
```

Turn the claim on in **Google Auth Platform → Data access** (or the project's
ID-token configuration). Without it Google returns no strength signal at all and
every Google sign-in lands at `Basic`, where the relay asks for its own second
factor (the emailed code, or an authenticator app).

Google's own documentation warns that `amr` **may be absent even when
requested**. The relay treats that as "not MFA" (`Basic`), never as "maybe MFA":
a second factor has to be asserted for *this* sign-in to count.

## 5. Configure the relay

```sh
WEAVER_SSO_GOOGLE_CLIENT_SECRET=<secret> \
  weaver-server sso google set --client-id <client-id>
```

The secret is sealed under `account.sso_key` with the associated data
`weaver-sso:google`, so it cannot be opened in another provider's slot.
`enable`, `disable`, `show` and `clear` manage the stored preset; restart the
daemon to apply a change.

For a local try against the real provider (plain HTTP on `localhost:43871`, the
development redirect URI the console registers):

```sh
WEAVER_SSO_GOOGLE_CLIENT_ID=<client-id> \
WEAVER_SSO_GOOGLE_CLIENT_SECRET=<secret> \
  cargo run -p weaver-server --example sso_dev_server
```

Emails print to stdout unless `WEAVER_RESEND_API_KEY` is set; with the capture
mailer, `http://localhost:43871/dev/mail` shows them in a browser.

## 6. Account status (not available from the token)

A disabled Google account never receives an ID token at all, so a sign-in cannot
detect it. That signal only exists through **Cross-Account Protection (RISC)**,
an optional per-provider extra that is not part of this preset: it needs a public
receiver endpoint, a Pub/Sub subscription and a service account, and it is off by
default. Until an operator builds it, the relay knows an account is gone only
when Google rejects its refresh grant — and a rejection means "the grant is no
longer valid", never "the account was deleted".

## Checklist

- [ ] Project and consent screen branded
- [ ] User type chosen (External or Internal)
- [ ] OAuth client of type **Web application**, redirect URI verbatim
- [ ] Client ID and secret copied
- [ ] External app **published to Production** if it must outlive 7 days
- [ ] `amr` claim enabled for the project
- [ ] Relay configured: client id, client secret
