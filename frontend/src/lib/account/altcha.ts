/**
 * Loads the vendored ALTCHA widget once and registers its PBKDF2 worker.
 *
 * The widget bundle is self-hosted same-origin under `{altcha_assets_base}` and
 * loaded at runtime with a dynamic `import()` — never an inline script, so it
 * stays inside the relay's strict `script-src 'self'` policy.
 */

let loading: Promise<void> | null = null;

export function loadAltcha(assetsBase: string): Promise<void> {
	if (loading) return loading;

	const base = assetsBase.endsWith('/') ? assetsBase : `${assetsBase}/`;

	loading = import(/* @vite-ignore */ `${location.origin}${base}altcha.js`)
		.then(() => {
			// Mirrors the relay's reference bootstrap: register exactly one
			// algorithm against the self-hosted worker.
			globalThis.$altcha?.algorithms?.set?.(
				'PBKDF2/SHA-256',
				() => new Worker(new URL(`${base}workers/pbkdf2.js`, location.origin), { type: 'module' })
			);
		})
		.catch((error) => {
			loading = null;
			throw error;
		});

	return loading;
}
