/**
 * The console's step-up guard.
 *
 * A session that has proven only the password is `basic`: the relay's gate
 * refuses every protected endpoint until the emailed code is accepted. Letting
 * an `/app` load run would just fire requests the relay answers with `403`, so
 * this load waits for the root session and sends the visitor back to the code
 * step first.
 *
 * It is a *load*, not only the `$effect` in the sibling layout: the pages'
 * own loads `await parent()`, so a redirect here happens before any page fetch
 * is issued. WVR-167.
 */
import { redirect } from '@sveltejs/kit';

import { resolve } from '$app/paths';

import type { LayoutLoad } from './$types';

export const load: LayoutLoad = async ({ parent }) => {
	const { session } = await parent();
	if (session?.auth_level === 'basic') {
		redirect(307, resolve('/(auth)/verify-code'));
	}
};
