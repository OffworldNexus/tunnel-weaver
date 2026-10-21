<script lang="ts">
	/**
	 * The personal overview: how much of the account is live, what it has moved
	 * over the reporting window, and the machines themselves. The stat blocks
	 * come from the relay's rollup; the list is the first page of the machines
	 * collection. No chart, no projection.
	 *
	 * The data arrives from the route's `load` before this renders, so there is
	 * no absent-versus-zero question to answer: every panel has the real figure.
	 * A machine action invalidates the shared `app:machines` key and the loader
	 * re-runs, so the panels follow the list.
	 */
	import type { BarGroup } from '#lib/app/chart';
	import { bytes, count } from '#lib/app/format';
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

	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let pairing = $state(false);

	setMeta({
		title: 'Overview',
		subtitle: 'Your account and the machines paired to it.',
		crumbs: [{ label: 'Overview' }]
	});

	/** The bar groups read straight off the rollup. */
	const composition = $derived([
		{
			label: 'Machines',
			active: data.stats.machines.online,
			total: data.stats.machines.total
		},
		{
			label: 'Tunnels',
			active: data.stats.tunnels.active,
			total: data.stats.tunnels.total
		}
	] satisfies BarGroup[]);

	/** The reporting window, its totals, and the span they actually cover. */
	const traffic = $derived({
		days: data.stats.window_days,
		usage: data.stats.usage_30d,
		covered: data.stats.covered_seconds
	});

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
</script>

<div class="grid grid--wide">
	<Panel title="Machines & tunnels" subtitle="Online machines and open service tunnels">
		<StackedBars groups={composition} />
	</Panel>

	<Panel title="Last {traffic.days} days" subtitle="Traffic the relay carried for this account">
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
	</Panel>
</div>

<Panel flush title="Machines" subtitle="{data.total} paired · click a row to open a machine">
	{#snippet actions()}
		<Keycap type="button" size="sm" variant="primary" onclick={() => (pairing = true)}>
			<Icon name="plus" size={15} /> Pair a machine
		</Keycap>
	{/snippet}

	{#if data.machines.length}
		<div class="table-wrap">
			<table class="table">
				<!-- Fixed widths, so no column moves as the list reloads. The last
				     column is the 17% MachineActions' action cluster needs: at the
				     console's narrowest desktop width (a 980px viewport) that is
				     ~159px, enough for its three 38px icon keycaps, their two 6px
				     gaps and the cell's 11px padding (148px). Percentages rather
				     than a pixel width because a fixed layout cannot mix the two
				     without the columns overshooting the table; keeping the five at
				     100% means they rebudget as the window resizes and
				     `.table-wrap` never grows a horizontal scrollbar. -->
				<colgroup>
					<col style="width: 32%" />
					<col style="width: 12%" />
					<col style="width: 16%" />
					<col style="width: 23%" />
					<col style="width: 17%" />
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
					{#each data.machines as machine (machine.id)}
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
								<MachineActions {machine} />
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

	{#snippet footer()}
		{#if data.total > data.machines.length}
			<div class="more">
				<span>
					Showing <span class="mono">{data.machines.length}</span> of
					<span class="mono">{data.total}</span> machines.
				</span>
				<Keycap href={resolve('/app/machines')} variant="key" size="sm">
					See all machines <Icon name="chevron-right" size={14} />
				</Keycap>
			</div>
		{/if}
	{/snippet}
</Panel>

<PairMachineDialog bind:open={pairing} />

<style lang="scss">
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
