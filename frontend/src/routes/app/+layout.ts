/**
 * The console's step-up guard.
 *
 * Everything under `/app` needs a `strong` session. A `basic` one (password
 * only) would just fire requests the relay refuses, so this load sends it up
 * the path the session stream names before any page load runs — the pages'
 * own loads `await parent()`, so the redirect lands before any of them fetch.
 * The sibling layout component follows the stream for drops after this.
 * WVR-167.
 */
import { redirect } from '@sveltejs/kit';

import { session } from '#lib/app/session.svelte';
import { stepRoute } from '#lib/app/upgrade';

import type { LayoutLoad } from './$types';

export const load: LayoutLoad = async ({ parent }) => {
	await parent();
	if (session.level === 'basic') {
		redirect(307, stepRoute(session.pathsTo('strong')[0]?.[0]?.step ?? 'verify_email_otp'));
	}
};
