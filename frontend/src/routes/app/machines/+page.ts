/**
 * The machines list's data. Paging, the name search and the health filter live
 * in the address bar — the URL is the single source of truth — and the loader
 * reads them back out, so a filtered page is linkable, the back button works,
 * and every navigation re-runs this with the new parameters.
 *
 * `depends('app:machines')` lets a machine action refresh the list (and the
 * overview, which shares the key) without a callback.
 */
import { unwrap } from '#lib/app/load';
import { listMachines, readHealth, readPage } from '#lib/app/machines';

import type { PageLoad } from './$types';

/**
 * A deliberately large page: a person with an ordinary handful of machines
 * never sees a second one, and the overview points here for the rest.
 */
const SIZE = 60;

export const load: PageLoad = async ({ url, depends, parent }) => {
	// Wait for the root and console layouts: the session stream has spoken and
	// the level is enough before this page issues a request of its own.
	await parent();
	depends('app:machines');

	const q = url.searchParams.get('q') ?? '';
	const health = readHealth(url.searchParams.get('health'));
	const page = readPage(url.searchParams.get('page'));

	const listed = unwrap(
		await listMachines({ page, perPage: SIZE, q, health }),
		'We could not load your machines. Please try again.'
	);

	return {
		machines: listed.machines,
		total: listed.total,
		page: listed.page,
		pageCount: listed.page_count,
		perPage: listed.per_page,
		q,
		health
	};
};
