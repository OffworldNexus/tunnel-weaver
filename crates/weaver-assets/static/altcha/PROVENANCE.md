# Vendored ALTCHA widget assets

Source: the official `altcha` web widget, npm package `altcha@3.3.0`
(<https://github.com/altcha-org/altcha>, tag `v3.3.0`), `dist/external` build.
License: MIT.

| File | Upstream path |
| --- | --- |
| `altcha.js` | `dist/external/altcha.js` |
| `altcha.css` | `dist/external/altcha.css` |
| `workers/pbkdf2.js` | `dist/workers/pbkdf2.js` |

`demo-bootstrap.js` is ours: it registers the single algorithm we support
(`PBKDF2/SHA-256`) against the self-hosted worker, since the `external` build
omits the bundled workers that the default `main` build carries.

The `external` build is chosen deliberately: it works under a strict CSP with no
`worker-src blob:` and no inline styles, which the default bundle requires.

To upgrade: bump the version above, re-download the three files from
`https://unpkg.com/altcha@<version>/…`, and refresh any golden fixture captured
from the widget (its protocol is pinned per release).
