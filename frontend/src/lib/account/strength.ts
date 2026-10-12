/**
 * A rough password-strength heuristic, for display only.
 *
 * The relay owns the real policy — a minimum length plus a breach check — and
 * enforces it authoritatively on submit. This exists purely to give the user a
 * live hint while typing, so a "strong" label here is never a guarantee.
 */

export interface Strength {
	level: 'weak' | 'fair' | 'strong';
	/** Fill percentage for the meter. */
	pct: number;
	/** Short label, or empty for an empty password. */
	label: string;
}

/** Scores a password on length and character-class variety. */
export function passwordStrength(value: string): Strength {
	let score = 0;
	if (value.length >= 8) score++;
	if (value.length >= 12) score++;
	if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score++;
	if (/\d/.test(value)) score++;
	if (/[^A-Za-z0-9]/.test(value)) score++;

	if (value.length === 0) return { level: 'weak', pct: 0, label: '' };
	if (score <= 2) return { level: 'weak', pct: 33, label: 'Weak' };
	if (score === 3) return { level: 'fair', pct: 66, label: 'Fair' };
	return { level: 'strong', pct: 100, label: 'Strong' };
}
