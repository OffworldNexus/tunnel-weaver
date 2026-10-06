# Tunnel Weaver account emails

Six proposed transactional emails, one shared MJML pattern. These are design
templates, not a new authentication or delivery implementation.

Figma: [05 · Emails](https://www.figma.com/design/NchadN1cA9ZZoWuJ35qZoM?node-id=40-2).
Individual variants: [verification](https://www.figma.com/design/NchadN1cA9ZZoWuJ35qZoM?node-id=40-3),
[welcome](https://www.figma.com/design/NchadN1cA9ZZoWuJ35qZoM?node-id=40-25),
[password recovery](https://www.figma.com/design/NchadN1cA9ZZoWuJ35qZoM?node-id=40-47),
[password changed](https://www.figma.com/design/NchadN1cA9ZZoWuJ35qZoM?node-id=40-69),
[new sign-in](https://www.figma.com/design/NchadN1cA9ZZoWuJ35qZoM?node-id=40-88),
[email 2FA](https://www.figma.com/design/NchadN1cA9ZZoWuJ35qZoM?node-id=40-109).

## Pattern

600 px, fluid single column. Text-only **Tunnel Weaver** header on neutral-900,
brand-300 amber rule, white body, neutral-50 footer. Olive-400 confirmation buttons
with olive-950 legends match the brand's confirm-key palette; underlined brand-900
text links remain legible on white. No mascot illustration or remote image dependency.

[Modern Font Stacks](https://modernfontstacks.com/) apply **only to emails**:

- Neo-Grotesque: `Inter, Roboto, 'Helvetica Neue', 'Arial Nova', 'Nimbus Sans', Arial, sans-serif`.
- Monospace Code: `ui-monospace, 'Cascadia Code', 'Source Code Pro', Menlo, Consolas, 'DejaVu Sans Mono', 'Courier New', monospace`.

No fonts are downloaded. Named fallbacks support older clients that ignore generic
`ui-monospace`. Figma uses Inter/Source Code Pro as stack representatives; recipient
fonts vary. The app's existing typography is unchanged.

Shared header, footer and head attributes live in `partials/`; variants declare
only their content. Tasks have one button plus a raw URL fallback. Security
notifications use text links. 2FA uses one selectable code, never split digit boxes.

| Template | Subject | Preview | Main content |
| --- | --- | --- | --- |
| `verification.mjml` | Verify your Tunnel Weaver email | Confirm your email address to continue. | Verify email button |
| `welcome.mjml` | Welcome to Tunnel Weaver | Your account is ready. | Open Tunnel Weaver button |
| `password-recovery.mjml` | Reset your Tunnel Weaver password | A link to choose a new password. | Reset password button |
| `password-changed.mjml` | Your Tunnel Weaver password was changed | If this wasn’t you, here’s what to do. | Event time; recovery/support links |
| `new-login.mjml` | A new sign-in to Tunnel Weaver | A sign-in from a device we haven’t seen before. | Device/time; recovery/support links |
| `two-factor.mjml` | Your Tunnel Weaver sign-in code | Use this code to finish signing in. | Code, expiry, safety copy |

Keep codes out of subject/preview. Sample dates, URLs, codes and expiry durations
in Figma are illustrative, not policy.

## Compile and render

From the repository root, compile each source path so relative includes resolve:

```sh
npx --yes --package=mjml@4.18.0 mjml docs/brand/emails/verification.mjml \
  --config.validationLevel strict -o /tmp/opencode/verification.html
```

`{{name}}` tokens are neutral placeholders, not a prescribed engine. Compile trusted
MJML first, then substitute using the sender's template engine. HTML-escape all
values including attributes; validate action/support URLs as trusted HTTPS URLs.
Reject missing values, avoid recursive substitution and never inject untrusted HTML.

Common values: `subject`, `preview`, `support_url`.

| Template | Additional values |
| --- | --- |
| Verification | `verification_url`, `expires_in` |
| Welcome | `account_url` |
| Password recovery | `reset_url`, `expires_in` |
| Password changed | `event_time`, `recovery_url` |
| New sign-in | `device_label`, `event_time`, `recovery_url` |
| Email 2FA | `code`, `expires_in`, `recovery_url` |

Include timezone in `event_time`; supply actual policy in `expires_in`. Preserve
leading zeros in `code`. `device_label` is best-effort browser/OS context, not proof
of identity. No invented location, IP or session-management controls. Recovery links
lead to normal password recovery, not pre-authorised actions. Send welcome only when
the account is ready, notifications only after confirmed events. Token expiry,
single-use protections and abuse controls belong to the sender, not these templates.

## Email-client constraints

MJML provides tables, inline styles and Outlook conditional markup. No web fonts,
SVG, background images, flex/grid, animation, shadows or hover-dependent controls.
Allow font/colour differences, dark-mode inversion and square corners in old clients.
Check real Gmail, Apple Mail and classic Windows Outlook, including mobile widths,
long URLs, dark mode and blocked images. Strict MJML compilation is not client testing.
Keep compiled HTML below Gmail's roughly 102 KB clipping threshold.

Send a plain-text alternative: heading/body, action URL or code, expiry/safety copy,
support URL. No tracking pixels, marketing content or extra onboarding sequence.
