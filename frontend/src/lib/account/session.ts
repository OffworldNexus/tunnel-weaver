/** Reads the script-readable double-submit CSRF cookie for logout. */

export const CSRF_COOKIE = '__Host-weaver_csrf';

export function readCookie(name: string): string | null {
	if (typeof document === 'undefined') return null;
	const escaped = name.replace(/([.*+?^${}()|[\]\\])/g, '\\$1');
	const match = document.cookie.match(new RegExp('(?:^|; )' + escaped + '=([^;]*)'));
	return match ? decodeURIComponent(match[1]) : null;
}

export function csrfToken(): string | null {
	return readCookie(CSRF_COOKIE);
}
