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

/**
 * Restricts a `next` target to a same-origin relative path (WVR-13).
 *
 * Anything that is not a single-slash absolute path — an absolute URL, a
 * scheme-relative `//host`, an empty value — falls back, so a crafted link
 * cannot turn sign-in into an open redirect.
 */
export function safeNext(value: string | undefined, fallback = '/app'): string {
	if (value && value.startsWith('/') && !value.startsWith('//')) return value;
	return fallback;
}
