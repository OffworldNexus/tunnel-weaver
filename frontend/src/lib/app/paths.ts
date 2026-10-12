import { resolve } from '$app/paths';

/**
 * Builds an app URL, including the base path (empty: the app owns the admin
 * host root).
 *
 * The SPA must never emit a bare route URL, so every link/navigation goes
 * through `resolve()`.
 */
export function href(path: string): string {
	return resolve(path as Parameters<typeof resolve>[0]);
}
