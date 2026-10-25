// SPA mode: no server rendering (the relay serves a static shell) and no
// prerendering (every history route is handled client-side and rewritten to
// `index.html` by the edge).
import { session } from '#lib/app/session.svelte';

import type { LayoutLoad } from './$types';

export const ssr = false;
export const prerender = false;

/**
 * Opens the session stream and holds the app until its first frame.
 *
 * The root layout's load runs before any page's, and the protected page loads
 * `await parent()` — so no page fetches anything before the level is known.
 * The stream then keeps the level current on its own; nothing here re-runs per
 * navigation.
 */
export const load: LayoutLoad = async () => {
	session.start();
	await session.settled();
};
