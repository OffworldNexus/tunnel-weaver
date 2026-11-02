import { api } from '#lib/account/api';

/** One enabled external identity provider, as the sign-in page shows it. */
export interface SsoProvider {
	/** The route segment and session-stream name, e.g. `google`. */
	id: string;
	/** The button text, e.g. `Google`. */
	label: string;
}

/** Client-facing constants the account SPA reads from the relay. */
export interface AccountConfig {
	altcha_challenge_url: string;
	altcha_assets_base: string;
	min_password_length: number;
	resend_cooldown_secs: number;
	support_email: string | null;
	/** The admin host the CLI dials to pair, for the `weave pair <host>` hint. */
	relay_host: string;
	/** The external identity providers the operator enabled (WVR-169, WVR-175). */
	sso_providers: SsoProvider[];
}

export const config = $state<{ value: AccountConfig | null }>({ value: null });

/**
 * The relay's minimum, mirrored for guidance; the relay enforces it on submit.
 * A function, not a value, so a read from inside a `$derived` is still tracked.
 */
export const minPasswordLength = (): number => config.value?.min_password_length ?? 8;

/**
 * The enabled external identity providers (WVR-169, WVR-175). A function, not a
 * value, so a read from inside a `$derived` is still tracked.
 */
export const ssoProviders = (): SsoProvider[] => config.value?.sso_providers ?? [];

/**
 * The display label for a provider id.
 *
 * The sign-in grid already carries every label, so this is mostly for the
 * session stream, which names only the provider that opened the session. An
 * unknown id is tidied rather than hidden.
 */
export function providerLabel(id: string): string {
	const known = ssoProviders().find((provider) => provider.id === id);
	if (known) {
		return known.label;
	}
	return id.replaceAll('-', ' ').replace(/^./, (first) => first.toUpperCase());
}

let loading: Promise<AccountConfig> | null = null;

/** Fetches `/api/account/config` once; a failed fetch is retried on the next call. */
export function ensureConfig(): Promise<AccountConfig> {
	loading ??= api<AccountConfig>('GET', '/api/account/config').then((res) => {
		if (!res.ok || !res.data) {
			loading = null;
			throw new Error(res.error ?? 'config unavailable');
		}
		config.value = res.data;
		return res.data;
	});
	return loading;
}
