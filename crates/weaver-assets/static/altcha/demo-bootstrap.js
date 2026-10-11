// Tunnel Weaver ALTCHA diagnostic bootstrap (WVR-136).
//
// The pinned upstream widget's `dist/external` build ships no algorithm
// workers: integrations register the ones they need. We support exactly one,
// PBKDF2/SHA-256, against our self-hosted worker. `altcha.js` runs first
// (module scripts execute in document order) and sets `globalThis.$altcha`.
const workerUrl = new URL("./workers/pbkdf2.js", import.meta.url);
globalThis.$altcha?.algorithms?.set?.(
  "PBKDF2/SHA-256",
  () => new Worker(workerUrl, { type: "module" }),
);

// The widget only auto-solves on submit from the `unverified` state. After the
// challenge expires it stays in `expired` with a stale payload, so a later
// submit would post the stale proof. Return it to `unverified` on expiry, so
// the next submit re-solves against a fresh challenge.
for (const widget of document.querySelectorAll("altcha-widget")) {
  widget.addEventListener("expired", () => widget.reset());
}
