/**
 * One machine's data: its identity, key fingerprint and the public hostnames it
 * serves, read through the same-origin account API. An id that is not a machine
 * of this account is an error, never an empty page.
 *
 * `depends('app:machines')` shares the machines key, so an action taken on the
 * list or the overview refreshes this page too.
 */
import { error } from '@sveltejs/kit';

import { unwrap } from '#lib/app/load';
import { getMachine } from '#lib/app/machines';

import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params, depends, parent }) => {
	// Wait for the root layout's session load first, so `GET /api/account/me`
	// is issued before this page's own requests.
	await parent();
	depends('app:machines');

	const id = Number(params.machine);
	if (!Number.isFinite(id) || id <= 0) {
		error(404, 'That machine does not belong to your account.');
	}

	const machine = unwrap(await getMachine(id), 'We could not load that machine. Please try again.');

	return { machine };
};
