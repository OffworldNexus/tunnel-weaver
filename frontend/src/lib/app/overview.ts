/**
 * The account-level rollup the console's stat blocks render: presence counts and
 * the traffic carried over the reporting window. Served by the relay rather than
 * re-summed in the browser.
 */
import { api } from '#lib/account/api';
import type { Usage30d } from '#lib/app/machines';

/** How many machines are paired, and how many are live. */
export interface MachineCounts {
	online: number;
	total: number;
}

/** How many service tunnels are declared, and how many are up. */
export interface TunnelCounts {
	active: number;
	total: number;
}

export interface OverviewStats {
	machines: MachineCounts;
	tunnels: TunnelCounts;
	usage_30d: Usage30d;
	/** The window the usage figures sum over, in days. */
	window_days: number;
	/**
	 * How many seconds of that window actually carried traffic. A rate divides by
	 * this and never by the nominal window: a relay that came up two minutes ago
	 * has two minutes of data, not thirty days, and a "rate" computed from the
	 * window alone is an invention.
	 */
	covered_seconds: number;
}

/** `GET /api/account/overview` — the signed-in account's rollup. */
export function getOverview() {
	return api<OverviewStats>('/api/account/overview');
}
