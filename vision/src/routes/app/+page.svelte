<script lang="ts">
	/**
	 * The top-level overview for the signed-in role:
	 * - Super admin: the fleet overview (composition, 30d counters, real-time
	 *   bandwidth, searchable active organisations).
	 * - Org admin: redirects to `/app/org` (their native organisation overview).
	 * - User: their own machines, tunnels and bandwidth (`PersonDetail`).
	 */
	import BandwidthChart from '#lib/console/BandwidthChart.svelte';
	import FleetOrgs from '#lib/console/FleetOrgs.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import StackedBars from '#lib/console/StackedBars.svelte';
	import { setMeta } from '#lib/console/meta';
	import { projectedBytes, projectedRequests } from '#lib/console/series';
	import { bytes, count } from '#lib/mock/format';
	import {
		clearSelection,
		current,
		machines,
		orgs,
		people,
		review
	} from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	import PersonDetail from './people/[person]/PersonDetail.svelte';

	onMount(() => {
		if ($current?.role === 'super_admin') {
			clearSelection();
		} else if ($current?.role === 'org_admin') {
			void goto('/app/org', { replaceState: true });
		}
	});

	$: role = $current?.role ?? 'user';
	$: if (role === 'super_admin') {
		setMeta({
			title: 'Overview',
			subtitle: 'Organisations, users, machines and bandwidth across the fleet.'
		});
	}

	$: users = $people.filter((p) => p.role === 'user');
	$: flagged = $review.filter((r) => r.verdict === 'pending');
	$: flaggedOrgs = $orgs.filter((o) => flagged.some((f) => f.orgId === o.id)).length;

	$: fleetProjected = projectedBytes($machines, 'both');
	$: fleetOut30 = projectedBytes($machines, 'out');
	$: fleetIn30 = projectedBytes($machines, 'in');
	$: fleetReq30 = projectedRequests($machines);

	$: composition = [
		{
			label: 'Organisations',
			active: $orgs.filter((o) => o.status === 'active').length,
			total: $orgs.length
		},
		{
			label: 'Users',
			active: users.filter((u) => u.status === 'active').length,
			total: users.length
		},
		{
			label: 'Machines',
			active: $machines.filter((m) => m.online).length,
			total: $machines.length
		}
	];
</script>

{#if role === 'super_admin'}
	{#if flagged.length}
		<a class="review-banner" href="/app/admin/review">
			<span class="review-banner__icon"><Icon name="alert" size={20} /></span>
			<span class="review-banner__text">
				<strong>{flagged.length} service{flagged.length === 1 ? '' : 's'} need review.</strong>
				The abuse ranker flagged traffic across {flaggedOrgs}
				organisation{flaggedOrgs === 1 ? '' : 's'}. Decide each one before it escalates.
			</span>
			<span class="review-banner__cta">Open the review queue →</span>
		</a>
	{/if}

	<div class="grid grid--wide">
		<Panel title="Fleet composition" subtitle="Active share of every organisation, user and machine">
			<StackedBars groups={composition} />
		</Panel>

		<Panel title="Last 30 days" subtitle="Projected from the current rate">
			<dl class="counters">
				<div>
					<dt>Bandwidth</dt>
					<dd class="mono">{bytes(fleetProjected)}</dd>
					<span class="counters__sub">
						{bytes(fleetOut30)} out · {bytes(fleetIn30)} in
					</span>
				</div>
				<div>
					<dt>Requests</dt>
					<dd class="mono">{count(fleetReq30)}</dd>
					<span class="counters__sub">{count(Math.round(fleetReq30 / 30))} per day</span>
				</div>
			</dl>
		</Panel>
	</div>

	<BandwidthChart
		machines={$machines}
		title="Real-time bandwidth"
		subtitle="Fleet-wide"
		height={260}
	/>

	<FleetOrgs />
{:else if role === 'user' && $current}
	<PersonDetail id={$current.person.id} />
{/if}

<style lang="scss">
	.review-banner {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 14px;
		padding: 14px 16px;
		border: 1.5px solid var(--tw-danger);
		border-radius: var(--tw-radius);
		background: color-mix(in srgb, var(--tw-danger) 12%, var(--tw-well));
		color: var(--tw-text);
		text-decoration: none;
	}

	.review-banner:hover {
		text-decoration: none;
		background: color-mix(in srgb, var(--tw-danger) 18%, var(--tw-well));
	}

	.review-banner__icon {
		display: grid;
		place-items: center;
		width: 40px;
		height: 40px;
		flex: none;
		border-radius: 999px;
		background: color-mix(in srgb, var(--tw-danger) 22%, transparent);
		color: var(--tw-danger);
	}

	.review-banner__text {
		flex: 1 1 320px;
		font-size: 14px;
		line-height: 1.5;
	}

	.review-banner__text strong {
		font-size: 15px;
	}

	.review-banner__cta {
		font-weight: 700;
		color: var(--tw-danger);
		white-space: nowrap;
	}

	.counters {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
		gap: 20px 22px;
		margin: 0;
	}

	.counters dt {
		font-size: 11px;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.counters dd {
		margin: 6px 0 2px;
		font-size: 30px;
		font-weight: 700;
		line-height: 1;
	}

	.counters__sub {
		color: var(--tw-muted);
		font-size: 13px;
	}
</style>
