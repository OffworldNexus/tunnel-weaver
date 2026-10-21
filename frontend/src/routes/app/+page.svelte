<script lang="ts">
	/**
	 * The personal overview: how much of the account is live, what it has moved
	 * over the reporting window, and the machines themselves. The stat blocks
	 * come from the relay's rollup; the list is the first page of the machines
	 * collection. No chart, no projection.
	 *
	 * Nothing on this page invents a value. While the rollup is absent the stat
	 * panels show a loader: "0 B" is a claim about the account, not a placeholder,
	 * and a page that cannot tell the difference is lying.
	 */
	import { onMount } from 'svelte';

	import type { BarGroup } from '#lib/app/chart';
	import { bytes, count } from '#lib/app/format';
	import { listMachines, type Machine } from '#lib/app/machines';
	import { getOverview, type OverviewStats } from '#lib/app/overview';
	import { timeAgo } from '#lib/app/time';
	import MachineActions from '#lib/console/MachineActions.svelte';
	import { setMeta } from '#lib/console/meta';
	import PairMachineDialog from '#lib/console/PairMachineDialog.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import HealthDot from '#lib/ui/HealthDot.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Panel from '#lib/ui/Panel.svelte';
	import StackedBars from '#lib/ui/StackedBars.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	/** How many machines the overview lists before pointing at the full list. */
	const ROWS = 10;

	/** The relay's rollup for this account, or nothing until it answers. */
	let stats = $state<OverviewStats | null>(null);
	/** The first page of the machines collection. */
	let machines = $state<Machine[]>([]);
	/** The collection's total, so the footer can point at the full list. */
	let total = $state(0);
	/** Whether the machines collection has answered at all. */
	let listed = $state(false);
	let error = $state('');
	let pairing = $state(false);

	setMeta({
		title: 'Overview',
		subtitle: 'Your account and the machines paired to it.',
		crumbs: [{ label: 'Overview' }]
	});

	/** The bar groups read straight off the rollup; no rollup, no bars. */
	const composition = $derived(
		stats === null
			? null
			: ([
					{
						label: 'Machines',
						active: stats.machines.online,
						total: stats.machines.total
					},
					{
						label: 'Tunnels',
						active: stats.tunnels.active,
						total: stats.tunnels.total
					}
				] satisfies BarGroup[])
	);

	/** The reporting window, its totals, and the span they actually cover. */
	const traffic = $derived(
		stats === null
			? null
			: { days: stats.window_days, usage: stats.usage_30d, covered: stats.covered_seconds }
	);

	/**
	 * The span the figures cover, said plainly. A daily average is only honest
	 * once there is a day of traffic behind it; below that the span itself is the
	 * truthful thing to show.
	 */
	function span(seconds: number): string {
		if (seconds < 3600) {
			return `${Math.max(1, Math.round(seconds / 60))} min`;
		}
		if (seconds < 86_400) {
			return `${Math.round(seconds / 3600)} h`;
		}
		return `${Math.round(seconds / 86_400)} days`;
	}

	onMount(async () => {
		const [overview, page] = await Promise.all([getOverview(), listMachines({ perPage: ROWS })]);
		if (!overview.ok || !overview.data) {
			error = overview.error ?? 'We could not load your account. Please try again.';
			return;
		}
		stats = overview.data;
		listed = true;
		if (page.ok && page.data) {
			machines = page.data.machines;
			total = page.data.total;
		}
	});

	/**
	 * Re-reads the short list after an action changed a machine. A failure is
	 * surfaced rather than leaving the old rows on screen as if nothing happened.
	 */
	async function reload() {
		const [overview, page] = await Promise.all([getOverview(), listMachines({ perPage: ROWS })]);
		if (overview.ok && overview.data) {
			stats = overview.data;
		}
		if (!page.ok || !page.data) {
			error = page.error ?? 'We could not reload your machines. Please try again.';
			return;
		}
		machines = page.data.machines;
		total = page.data.total;
	}
</script>

{#if error}
	<p class="notice-error" role="alert">{error}</p>
{/if}

<div class="grid grid--wide">
	<Panel title="Machines & tunnels" subtitle="Online machines and open service tunnels">
		{#if composition}
			<StackedBars groups={composition} />
		{:else}
			<p class="state" aria-live="polite">Loading…</p>
		{/if}
	</Panel>

	<Panel
		title={traffic === null ? 'Traffic' : `Last ${traffic.days} days`}
		subtitle="Traffic the relay carried for this account"
	>
		{#if traffic}
			<dl class="counters">
				<div>
					<dt>Bandwidth</dt>
					<dd class="mono">{bytes(traffic.usage.bytes_in + traffic.usage.bytes_out)}</dd>
					<span class="counters__sub">
						{bytes(traffic.usage.bytes_out)} out · {bytes(traffic.usage.bytes_in)} in
					</span>
				</div>
				<div>
					<dt>Requests</dt>
					<dd class="mono">{count(traffic.usage.requests)}</dd>
					<span class="counters__sub">
						{#if traffic.covered >= 86_400}
							{count(Math.round(traffic.usage.requests / (traffic.covered / 86_400)))} per day
						{:else}
							over {span(traffic.covered)}
						{/if}
					</span>
				</div>
			</dl>
		{:else}
			<p class="state" aria-live="polite">Loading…</p>
		{/if}
	</Panel>
</div>

<Panel
	flush
	title="Machines"
	subtitle={listed
		? `${total} paired · click a row to open a machine`
		: 'The machines paired to your account'}
>
	<svelte:fragment slot="actions">
		<Keycap type="button" size="sm" variant="primary" onclick={() => (pairing = true)}>
			<Icon name="plus" size={15} /> Pair a machine
		</Keycap>
	</svelte:fragment>

	{#if !listed}
		<p class="state" aria-live="polite">Loading your machines…</p>
	{:else if machines.length}
		<div class="table-wrap">
			<table class="table">
				<colgroup>
					<col style="width: 30%" />
					<col style="width: 15%" />
					<col style="width: 20%" />
					<col style="width: 25%" />
					<col style="width: 10%" />
				</colgroup>
				<thead>
					<tr>
						<th>Machine</th>
						<th>Health</th>
						<th>Last seen</th>
						<th class="right">Bandwidth · 30d</th>
						<th class="right"></th>
					</tr>
				</thead>
				<tbody>
					{#each machines as machine (machine.id)}
						<tr
							class="row-link"
							role="link"
							tabindex="0"
							onclick={(event) => {
								if ((event.target as HTMLElement).closest('.row-actions')) {
									return;
								}
								void goto(resolve('/app/machines/[machine]', { machine: `${machine.id}` }));
							}}
							onkeydown={(event) => {
								if ((event.target as HTMLElement).closest('.row-actions')) {
									return;
								}
								if (event.key === 'Enter' || event.key === ' ') {
									event.preventDefault();
									void goto(resolve('/app/machines/[machine]', { machine: `${machine.id}` }));
								}
							}}
						>
							<td><span class="cell-name">{machine.name}</span></td>
							<td><HealthDot online={machine.online} /></td>
							<td class="mono nowrap">{timeAgo(machine.last_seen_at)}</td>
							<td class="mono nowrap right">
								{bytes(machine.usage_30d.bytes_in + machine.usage_30d.bytes_out)}
							</td>
							<td class="right">
								<MachineActions {machine} onchange={reload} />
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{:else}
		<EmptyState
			icon="machine"
			title="No machines yet"
			text="Pair a machine with `weave pair` to expose a service through the relay."
		/>
	{/if}

	<svelte:fragment slot="footer">
		{#if total > machines.length}
			<div class="more">
				<span>
					Showing <span class="mono">{machines.length}</span> of <span class="mono">{total}</span> machines.
				</span>
				<Keycap href={resolve('/app/machines')} variant="key" size="sm">
					See all machines <Icon name="chevron-right" size={14} />
				</Keycap>
			</div>
		{/if}
	</svelte:fragment>
</Panel>

<PairMachineDialog bind:open={pairing} />

<style lang="scss">
	.notice-error {
		margin: 0;
	}

	.state {
		padding: 24px 16px;
		color: var(--tw-muted);
	}

	.counters {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
		gap: 16px;
		margin: 0;
	}

	.counters div {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.counters dt {
		font-size: 12px;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.counters dd {
		margin: 0;
		font-size: 28px;
		font-weight: 700;
		line-height: 1.1;
		letter-spacing: -0.02em;
	}

	.counters__sub {
		color: var(--tw-muted);
		font-size: 13px;
	}

	.table-wrap {
		overflow-x: auto;
	}

	.row-link {
		cursor: pointer;
	}

	.row-link:hover {
		background: color-mix(in srgb, var(--tw-accent) 8%, transparent);
	}

	.cell-name {
		display: block;
		font-weight: 700;
		color: var(--tw-text);
		overflow-wrap: anywhere;
	}

	.more {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
	}
</style>
