/** Display formatters shared by the console. */

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];

/** A byte count, e.g. `944.0 MB`. */
export function bytes(n: number, digits = 1): string {
	if (n <= 0) {
		return '0 B';
	}
	const i = Math.min(UNITS.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
	const value = n / 1024 ** i;
	return `${value.toFixed(i === 0 ? 0 : digits)} ${UNITS[i]}`;
}

/** A large count in short form, e.g. `7.4M`. */
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
