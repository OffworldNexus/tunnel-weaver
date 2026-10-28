/**
 * The Security page's data, through its loader.
 *
 * `depends('app:security')` is what every action on the page invalidates, so an
 * app confirmed or a passkey removed re-runs *this* and the page re-renders from
 * the relay's answer — instead of each panel holding a list of its own, which is
 * how the lists came to arrive one after another (and to stay wrong after a
 * refusal, with a row the relay had created and the page had never seen).
 */
import { unwrap } from '#lib/app/load';
import { loadSecurity } from '#lib/app/security';

import type { PageLoad } from './$types';

export const load: PageLoad = async ({ depends, parent }) => {
	// Wait for the layout: the session stream has spoken, so the level is known
	// before this page issues a request that needs one.
	await parent();
	depends('app:security');

	return {
		security: unwrap(await loadSecurity(), 'We could not read your security settings.')
	};
};
