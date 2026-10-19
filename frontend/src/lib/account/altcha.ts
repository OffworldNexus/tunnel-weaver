/**
 * Loads the vendored ALTCHA widget once and registers its PBKDF2 worker.
 *
 * The bundle is self-hosted same-origin and loaded with a dynamic `import()`,
 * never an inline script, so it stays inside the relay's `script-src 'self'`.
 */

let loading: Promise<void> | null = null;

export function loadAltcha(base: string): Promise<void> {
	loading ??= import(/* @vite-ignore */ `${location.origin}${base}altcha.js`).then(
		() => {
			globalThis.$altcha.algorithms.set(
				'PBKDF2/SHA-256',
				() => new Worker(new URL(`${base}workers/pbkdf2.js`, location.origin), { type: 'module' })
			);
		},
		(error) => {
			loading = null;
			throw error;
		}
	);
	return loading;
}
