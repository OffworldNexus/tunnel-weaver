/**
 * Timestamp formatting for the account surface. The relay sends absolute Unix
 * seconds; `null` means "no such time", which every caller renders as `—` rather
 * than inventing one.
 */

/** A relative "N ago" label for a Unix-seconds timestamp, or `never` for none. */
export function timeAgo(unixSeconds: number | null): string {
	if (unixSeconds === null) {
		return 'never';
	}
	const secs = Math.round(Date.now() / 1000 - unixSeconds);
	if (secs < 5) {
		return 'just now';
	}
	if (secs < 60) {
		return `${secs}s ago`;
	}
	const mins = Math.round(secs / 60);
	if (mins < 60) {
		return `${mins}m ago`;
	}
	const hours = Math.round(mins / 60);
	if (hours < 24) {
		return `${hours}h ago`;
	}
	const days = Math.round(hours / 24);
	return `${days}d ago`;
}

/** A short absolute date for a Unix-seconds timestamp, or `—` for none. */
export function date(unixSeconds: number | null): string {
	if (unixSeconds === null) {
		return '—';
	}
	return new Date(unixSeconds * 1000).toLocaleDateString(undefined, {
		year: 'numeric',
		month: 'short',
		day: 'numeric'
	});
}
