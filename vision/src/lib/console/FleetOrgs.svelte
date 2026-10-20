<script lang="ts">
	/**
	 * The super-admin organisation list on the overview: searchable, paginated,
	 * active organisations only. Each row shows active/total users and machines
	 * with their own mini bar graphs, plus an inline graph of external bandwidth
	 * (in + out). Clicking a row selects that organisation and opens its overview.
	 */
	import { bytes, count } from '#lib/mock/format';
	import { machines, orgs, people, selectOrg } from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	import EmptyState from './EmptyState.svelte';
	import MiniBar from './MiniBar.svelte';
	import Pagination from './Pagination.svelte';
	import Panel from './Panel.svelte';
	import Reputation from './Reputation.svelte';
	import Spark from './Spark.svelte';
	import { paginate } from './paginate';
	import { externalSeries, hourlyBytes, projectedBytes } from './series';

	let q = '';
	let page = 1;
	const SIZE = 8;

	$: rows = $orgs
		.filter((org) => org.status !== 'suspended')
		.map((org) => {
			const users = $people.filter((p) => p.orgId === org.id && p.role === 'user');
			const ids = new Set(users.map((u) => u.id));
			const orgMachines = $machines.filter((m) => ids.has(m.personId));
			return {
				org,
				usersActive: users.filter((u) => u.status === 'active').length,
				usersTotal: users.length,
				machinesActive: orgMachines.filter((m) => m.online).length,
				machinesTotal: orgMachines.length,
				requestsHour: orgMachines.reduce(
					(a, m) => a + m.services.reduce((x, s) => x + s.requestsHour, 0),
					0
				),
				bandwidthHour: hourlyBytes(orgMachines, 'bytesIn') + hourlyBytes(orgMachines, 'bytesOut'),
				bandwidth30d: projectedBytes(orgMachines, 'both'),
				spark: externalSeries(orgMachines)
			};
		})
		.filter((row) => {
			const hay = `${row.org.name} ${row.org.slug}`.toLowerCase();
			return q === '' || hay.includes(q.toLowerCase());
		})
		.sort((a, b) => b.bandwidth30d - a.bandwidth30d);

	const filterKey = () => q;
	let lastKey = '';
	$: {
		const key = filterKey();
		if (key !== lastKey) {
			lastKey = key;
			page = 1;
		}
	}

	$: paged = paginate(rows, page, SIZE);

	function open(orgId: string) {
		selectOrg(orgId);
		void goto('/app/org');
	}
</script>

<Panel flush title="Organisations" subtitle="{rows.length} active · click a row to enter">
	<svelte:fragment slot="actions">
		<Keycap size="sm" variant="key" href="/app/admin/orgs">Manage all</Keycap>
	</svelte:fragment>

	<div class="toolbar">
		<label class="searchbox">
			<Icon name="search" size={16} />
			<input class="searchbox__input" type="search" placeholder="Filter organisations" bind:value={q} />
		</label>
		<span class="toolbar__spacer"></span>
	</div>

	{#if paged.total}
		<div class="table-wrap">
			<table class="table">
				<thead>
					<tr>
						<th>Organisation</th>
						<th>Users</th>
						<th>Machines</th>
						<th class="right">Req/h</th>
						<th>External bandwidth · 1h</th>
						<th class="right">Bandwidth · 30d</th>
						<th>Reputation</th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					{#each paged.items as row (row.org.id)}
						<!-- svelte-ignore a11y_no_noninteractive_element_interactions, a11y_click_events_have_key_events -->
						<tr
							class="row-link"
							role="link"
							tabindex="0"
							on:click={() => open(row.org.id)}
							on:keydown={(e) => {
								if (e.key === 'Enter' || e.key === ' ') {
									e.preventDefault();
									open(row.org.id);
								}
							}}
						>
							<td>
								<span class="cell-name">{row.org.name}</span>
								<span class="cell-sub mono">{row.org.slug}</span>
							</td>
							<td>
								<MiniBar active={row.usersActive} total={row.usersTotal} />
							</td>
							<td>
								<MiniBar active={row.machinesActive} total={row.machinesTotal} />
							</td>
							<td class="right mono">{count(row.requestsHour)}</td>
							<td>
								<span class="bw-cell">
									<span class="spark"><Spark data={row.spark} color="var(--tw-c1)" height={26} /></span>
									<span class="bw-cell__val mono">{bytes(row.bandwidthHour)}</span>
								</span>
							</td>
							<td class="right mono">{bytes(row.bandwidth30d)}</td>
							<td><Reputation score={row.org.reputation} compact /></td>
							<td class="right"><Icon name="arrow-right" size={15} /></td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<Pagination
			page={paged.page}
			pageCount={paged.pageCount}
			total={paged.total}
			from={paged.from}
			to={paged.to}
			unit="organisations"
			onPage={(p) => (page = p)}
		/>
	{:else}
		<EmptyState icon="building" title="No organisations match" />
	{/if}
</Panel>

<style lang="scss">
	.searchbox {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		height: 32px;
		padding: 0 10px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
		color: var(--tw-muted);
	}

	.searchbox__input {
		border: 0;
		background: none;
		color: var(--tw-text);
		font: 400 13px/1 var(--tw-sans);
		outline: none;
		width: 220px;
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
	}

	.cell-sub {
		display: block;
		font-size: 12px;
		color: var(--tw-muted);
	}

	.bw-cell {
		display: inline-flex;
		align-items: center;
		gap: 10px;
	}

	.spark {
		display: block;
		width: 110px;
		height: 26px;
	}

	.bw-cell__val {
		font-size: 12px;
		color: var(--tw-muted);
		min-width: 62px;
		text-align: right;
	}
</style>
