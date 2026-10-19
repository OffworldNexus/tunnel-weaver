import { derived, writable } from 'svelte/store';

import { api } from '#lib/account/api';

/** Client-facing constants the account SPA reads from the relay. */
export interface AccountConfig {
	altcha_challenge_url: string;
	altcha_assets_base: string;
	min_password_length: number;
	resend_cooldown_secs: number;
	support_email: string | null;
}

export const config = writable<AccountConfig | null>(null);

/** The relay's minimum, mirrored for guidance; the relay enforces it on submit. */
export const minPasswordLength = derived(config, ($config) => $config?.min_password_length ?? 8);

let loading: Promise<AccountConfig> | null = null;

/** Fetches `/api/account/config` once; a failed fetch is retried on the next call. */
export function ensureConfig(): Promise<AccountConfig> {
	loading ??= api<AccountConfig>('/api/account/config').then((res) => {
		if (!res.ok || !res.data) {
			loading = null;
			throw new Error(res.error ?? 'config unavailable');
		}
		config.set(res.data);
		return res.data;
	});
	return loading;
}
