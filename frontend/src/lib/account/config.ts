import { get, writable } from 'svelte/store';

/** Client-facing constants the account SPA reads from the relay. */
export interface AccountConfig {
	altcha_challenge_url: string;
	altcha_assets_base: string;
	min_password_length: number;
	verification_ttl_secs: number;
	resend_cooldown_secs: number;
	/** A monitored support address, or null when the relay has none configured. */
	support_email?: string | null;
}

export const config = writable<AccountConfig | null>(null);

let inflight: Promise<AccountConfig> | null = null;

/**
 * Fetches `/api/account/config` once and caches it in a store. The minimum
 * password length and ALTCHA asset base are read from here — never hardcoded.
 */
export function ensureConfig(): Promise<AccountConfig> {
	const current = get(config);
	if (current) return Promise.resolve(current);
	if (inflight) return inflight;

	inflight = fetch('/api/account/config', {
		credentials: 'same-origin',
		headers: { accept: 'application/json' }
	})
		.then(async (response) => {
			if (!response.ok) throw new Error('config unavailable');
			return (await response.json()) as AccountConfig;
		})
		.then((value) => {
			config.set(value);
			return value;
		})
		.catch((error) => {
			inflight = null;
			throw error;
		});

	return inflight;
}
