/**
 * The overview's data: the account rollup and the first page of the machines
 * collection, read through the same-origin account API.
 *
 * `depends('app:machines')` ties this to the machines list: a machine action
 * invalidates that key and this loader re-runs, so the stat panels follow the
 * list without either page knowing about the other.
 */
import { unwrap } from '#lib/app/load';
import { listMachines } from '#lib/app/machines';
import { getOverview, OVERVIEW_ROWS } from '#lib/app/overview';

import type { PageLoad } from './$types';

export const load: PageLoad = async ({ depends }) => {
	depends('app:machines');

	const [overview, page] = await Promise.all([
		getOverview(),
		listMachines({ perPage: OVERVIEW_ROWS })
	]);
	const stats = unwrap(overview, 'We could not load your account. Please try again.');
	const listed = unwrap(page, 'We could not load your machines. Please try again.');

	return { stats, machines: listed.machines, total: listed.total };
};
