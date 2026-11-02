# Microsoft Entra ID — registering the app for the SSO preset

Steps an operator has to follow to enable the Microsoft identity provider
(WVR-169, provider registry since WVR-175). Values appear as `<placeholders>`.

## 1. A tenant

The app registration lives in an Entra ID **tenant**. Create a directory
(`<name>.onmicrosoft.com`) and make your account Global Administrator.

## 2. Register the app

**Entra ID → App registrations → New registration**

- **Name** — shown on the consent screen.
- **Supported account types** — *Accounts in any organizational directory
  (multitenant) and personal Microsoft accounts*; single tenant for a private
  relay.
- **Redirect URI** — platform **Web**, matching the relay verbatim (a mismatch is
  `AADSTS50011`):
  - development: `http://localhost:43871/api/account/sso/microsoft/callback`
  - production: `https://<admin-domain>/api/account/sso/microsoft/callback`

**Certificates & secrets → New client secret** — copy the **Value**, shown once.

Three values go into the relay: **authority** (tenant GUID, or `common` /
`organizations` / `consumers`), **client id**, **client secret**.

## 3. A verified domain

**Custom domain names → Add custom domain** → `<your-domain>`, then add the TXT
record it gives you:

```
TXT   @   MS=ms########
```

**App registration → Branding & properties → Publisher domain** → select the
verified domain.

## 4. Branding

**Branding & properties → Upload new logo** — a **48×48 or 50×50** transparent
PNG/GIF/JPEG, **≤ 15 KB**. Home page URL, terms and privacy links are free text.

## 5. MFA (the tenant's decision, not the app's)

MFA policy belongs to the **signing-in user's tenant**; the app only reads the
result (`mfa` in `amr`). A sign-in without it lands at `Basic` and the relay asks
for its own second factor (the emailed code, or an authenticator app).

To have Entra perform MFA on **every** sign-in, in a tenant you administer:

- **Conditional Access** policy requiring MFA (needs Entra ID P1), or
- **Per-user MFA** set to *Enforced* (free; turn security defaults off first).

Security defaults alone do not do it: they only challenge users when Entra
judges a sign-in risky.

## 6. Consent

Consent is asked on first sign-in and again after any permission change. End users
of a multitenant app cannot consent without a **verified publisher** (MPN ID from
Partner Center); a tenant administrator can always consent.

## 7. Configure the relay

```sh
WEAVER_SSO_MICROSOFT_CLIENT_SECRET=<secret> \
  weaver-server sso microsoft set --authority <authority> --client-id <client-id>
```

The secret is sealed under `account.sso_key`. `enable`, `disable`, `show` and
`clear` manage the stored preset; restart the daemon to apply a change.

For a local try against the real tenant (plain HTTP on `localhost:43871`, the
development redirect URI):

```sh
WEAVER_SSO_MICROSOFT_AUTHORITY=<authority> \
WEAVER_SSO_MICROSOFT_CLIENT_ID=<client-id> \
WEAVER_SSO_MICROSOFT_CLIENT_SECRET=<secret> \
  cargo run -p weaver-server --example sso_dev_server
```

Emails print to stdout unless `WEAVER_RESEND_API_KEY` is set.

## Checklist

- [ ] Tenant, with you as Global Administrator
- [ ] App registration: name, account types, **Web** redirect URI verbatim
- [ ] Client secret copied
- [ ] Domain TXT-verified; publisher domain set
- [ ] Logo 48/50 px, ≤ 15 KB
- [ ] MFA enforced in the tenant, if Entra should drive `Strong`
- [ ] Relay configured: authority, client id, client secret
