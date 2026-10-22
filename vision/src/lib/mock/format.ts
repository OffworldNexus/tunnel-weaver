/** Display formatters shared by the console. */

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];

export function bytes(n: number, digits = 1): string {
	if (n <= 0) {
		return '0 B';
	}
	const i = Math.min(UNITS.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
	const value = n / 1024 ** i;
	return `${value.toFixed(i === 0 ? 0 : digits)} ${UNITS[i]}`;
}

/** Bytes per second, from a per-minute sample. */
export function rate(bytesPerMinute: number): string {
	return `${bytes(bytesPerMinute / 60)}/s`;
}

export function count(n: number): string {
	if (n >= 1_000_000) {
		return `${(n / 1_000_000).toFixed(1)}M`;
	}
	if (n >= 10_000) {
		return `${(n / 1000).toFixed(0)}k`;
	}
	if (n >= 1000) {
		return `${(n / 1000).toFixed(1)}k`;
	}
	return String(n);
}

export function percent(n: number, digits = 1): string {
	return `${(n * 100).toFixed(digits)}%`;
}

export function ms(n: number): string {
	if (n >= 1000) {
		return `${(n / 1000).toFixed(1)} s`;
	}
	return `${Math.round(n)} ms`;
}

export function timeAgo(iso: string): string {
	if (!iso) {
		return 'never';
	}
	const secs = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
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

export function clock(ts: number): string {
	return new Date(ts).toLocaleTimeString(undefined, { hour12: false });
}

export function date(iso: string): string {
	if (!iso) {
		return '—';
	}
	return new Date(iso).toLocaleDateString(undefined, {
		year: 'numeric',
		month: 'short',
		day: 'numeric'
	});
}

export function ago(ms: number): string {
	const secs = Math.round(ms / 1000);
	if (secs < 60) {
		return `${secs}s`;
	}
	const mins = Math.round(secs / 60);
	if (mins < 60) {
		return `${mins}m`;
	}
	return `${Math.round(mins / 60)}h`;
}
