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
import { stepPage } from '#lib/app/upgrade';
import { resolve } from '$app/paths';

import type { LayoutLoad } from './$types';

export const load: LayoutLoad = async ({ parent }) => {
	await parent();
	// The console needs `strong`. A session that only proved the password is sent
	// up the way the relay names — in practice the emailed-code page, the one
	// step the nominal flow still owes it. A step the console could do in place
	// has no page to redirect to and is left to the layout's own guard.
	if (session.level === 'basic') {
		const page = stepPage(session.pathsTo('strong')[0]?.[0]?.step ?? 'verify_email_otp');
		if (page) {
			redirect(307, resolve(page));
		}
	}
};
