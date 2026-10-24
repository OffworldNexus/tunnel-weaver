// SPA mode: no server rendering (the relay serves a static shell) and no
// prerendering (every history route is handled client-side and rewritten to
// `index.html` by the edge).
import { api } from '#lib/account/api';
import type { Me } from '#lib/app/session.svelte';

import type { LayoutLoad } from './$types';

export const ssr = false;
export const prerender = false;

/**
 * Reads the session before the destination's own loads run.
 *
 * SvelteKit starts a route's loaders together but in branch order — the root
 * layout first — so this makes `GET /api/account/me` the first request of every
 * navigation; the protected page loads `await parent()` to make sure their own
 * requests wait for it. `url.pathname` is read so a layout load is not reused:
 * the session is re-checked on every page change, and a failed probe fails
 * loudly rather than being mistaken for a signed-out visitor.
 */
export const load: LayoutLoad = async ({ url }) => {
	// Reading the pathname is what marks this load as URL-dependent, so it
	// re-runs whenever the page changes.
	void url.pathname;

	const res = await api<Me>('/api/account/me');
	if (res.ok && res.data) {
		return { session: res.data, error: '' };
	}
	if (res.status === 401) {
		return { session: null, error: '' };
	}
	return {
		session: null,
		error: res.error ?? 'We could not verify your session. Try again.'
	};
};
