<script lang="ts">
	/** The machine list for the active user. */
	import ConfirmDeleteDialog from '#lib/console/ConfirmDeleteDialog.svelte';
	import Dialog from '#lib/console/Dialog.svelte';
	import EmptyState from '#lib/console/EmptyState.svelte';
	import HealthDot from '#lib/console/HealthDot.svelte';
	import MiniBar from '#lib/console/MiniBar.svelte';
	import Pagination from '#lib/console/Pagination.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import Reputation from '#lib/console/Reputation.svelte';
	import Spark from '#lib/console/Spark.svelte';
	import { setMeta } from '#lib/console/meta';
	import { paginate } from '#lib/console/paginate';
	import { externalSeries, hourlyBytes, projectedBytes } from '#lib/console/series';
	import { notify } from '#lib/account/notices';
	import { bytes, timeAgo } from '#lib/mock/format';
	import {
		activePerson,
		current,
		healthOf,
		kickMachine,
		renameMachine,
		unpairMachine,
		visibleMachines
	} from '#lib/mock/store';
	import type { Machine } from '#lib/mock/types';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	let q = '';
	let status = 'all';
	let pairing = false;
	let page = 1;
	const SIZE = 10;

	let renamingTarget: Machine | null = null;
	let renameValue = '';
	let kickingTarget: Machine | null = null;
	let unpairingTarget: Machine | null = null;

	$: isSelf = $current?.role === 'user';
	$: canModerate = $current?.role === 'org_admin' || $current?.role === 'super_admin';

	$: setMeta({
		title: 'Machines',
		subtitle: isSelf
			? 'Every machine paired to your account.'
			: `Machines paired to ${$activePerson?.name ?? 'this account'}.`,
		crumbs: [
			...(!isSelf && $activePerson
				? [{ label: $activePerson.name, href: `/app/people/${$activePerson.id}` }]
				: []),
			{ label: 'Machines' }
		]
	});

	$: rows = $visibleMachines
		.filter((m) => {
			const hay = `${m.name} ${m.hostname} ${m.os} ${m.services.map((s) => s.name).join(' ')}`.toLowerCase();
			const okQ = q === '' || hay.includes(q.toLowerCase());
			const okStatus = status === 'all' || healthOf(m) === status;
			return okQ && okStatus;
		})
		.map((machine) => {
			const openServices = machine.services.filter((s) => s.tunnel === 'open');
			const scores = machine.services.map((s) => s.reputation);
			return {
				machine,
				health: healthOf(machine),
				tunnelsOpen: openServices.length,
				tunnelsTotal: machine.services.length,
				bandwidthHour: hourlyBytes([machine], 'bytesIn') + hourlyBytes([machine], 'bytesOut'),
				bandwidth30d: projectedBytes([machine], 'both'),
				spark: externalSeries([machine]),
				reputation: scores.length ? Math.min(...scores) : 100
			};
		});

	const filterKey = () => `${q}|${status}`;
	let lastKey = '';
	$: {
		const key = filterKey();
		if (key !== lastKey) {
			lastKey = key;
			page = 1;
		}
	}

	$: paged = paginate(rows, page, SIZE);

	function startRename(m: Machine) {
		renamingTarget = m;
		renameValue = m.name;
	}

	function confirmRename() {
		if (!renamingTarget || !/^[a-z0-9]{1,15}$/.test(renameValue)) {
			return;
		}
		renameMachine(renamingTarget.id, renameValue);
		notify('success', `Renamed to ${renameValue}. Hostnames follow immediately.`);
		renamingTarget = null;
	}

	function confirmUnpair() {
		if (!unpairingTarget) {
			return;
		}
		unpairMachine(unpairingTarget.id);
		unpairingTarget = null;
		notify('success', 'Machine unpaired and its tunnel dropped.');
	}

	function confirmKick() {
		if (!kickingTarget) {
			return;
		}
		kickMachine(kickingTarget.id);
		notify(
			'success',
			`Disconnected ${kickingTarget.name}. Reconnect from the machine with weave start.`
		);
		kickingTarget = null;
	}
</script>

<Panel flush title="Machines" subtitle="{rows.length} shown · click a row to inspect services, graphs and live logs">
	<svelte:fragment slot="actions">
		{#if isSelf}
			<Keycap type="button" size="sm" variant="primary" onclick={() => (pairing = true)}>
				<Icon name="plus" size={15} /> Pair a machine
			</Keycap>
		{/if}
	</svelte:fragment>

	<div class="toolbar">
		<label class="searchbox">
			<Icon name="search" size={16} />
			<input class="searchbox__input" type="search" placeholder="Name, hostname or service" bind:value={q} />
		</label>
		<select class="control control--sm" bind:value={status} aria-label="Filter by status">
			<option value="all">Any status</option>
			<option value="online">Online</option>
			<option value="idle">Idle</option>
			<option value="offline">Offline</option>
		</select>
		<span class="toolbar__spacer"></span>
	</div>

	{#if paged.total}
		<div class="table-wrap">
			<table class="table">
				<thead>
					<tr>
						<th>Machine</th>
						<th>Health</th>
						<th>Tunnels</th>
						<th>Open services</th>
						<th>External bandwidth · 1h</th>
						<th class="right">Bandwidth · 30d</th>
						{#if canModerate}<th>Reputation</th>{/if}
						<th></th>
					</tr>
				</thead>
				<tbody>
					{#each paged.items as row (row.machine.id)}
						<!-- svelte-ignore a11y_no_noninteractive_element_interactions, a11y_click_events_have_key_events -->
						<tr
							class="row-link"
							role="link"
							tabindex="0"
							on:click={() => void goto(`/app/machines/${row.machine.id}`)}
							on:keydown={(e) => {
								if (e.key === 'Enter' || e.key === ' ') {
									e.preventDefault();
									void goto(`/app/machines/${row.machine.id}`);
								}
							}}
						>
							<td>
								<span class="cell-name">{row.machine.name}</span>
								<span class="cell-sub mono">{row.machine.hostname} · {row.machine.os}</span>
							</td>
							<td>
								<HealthDot health={row.health} />
								<span class="cell-sub">{timeAgo(row.machine.lastSeenAt)}</span>
							</td>
							<td>
								<MiniBar active={row.tunnelsOpen} total={row.tunnelsTotal} />
							</td>
							<td>
								<div class="svc-pills">
									{#each row.machine.services as svc (svc.id)}
										<span class="svc-pill mono" class:open={svc.tunnel === 'open'}>
											{svc.name}
										</span>
									{/each}
								</div>
							</td>
							<td>
								<span class="bw-cell">
									<span class="spark"><Spark data={row.spark} color="var(--tw-c1)" height={26} /></span>
									<span class="bw-cell__val mono">{bytes(row.bandwidthHour)}</span>
								</span>
							</td>
							<td class="right mono">{bytes(row.bandwidth30d)}</td>
							{#if canModerate}
								<td><Reputation score={row.reputation} compact /></td>
							{/if}
							<td class="right" on:click|stopPropagation>
								<div class="row-actions">
									{#if row.machine.online}
										<Keycap
											type="button"
											size="sm"
											variant="ghost"
											onclick={() => (kickingTarget = row.machine)}
										>
											<Icon name="power" size={14} /> Kick
										</Keycap>
									{/if}
									<Keycap
										type="button"
										size="sm"
										variant="ghost"
										title="Rename {row.machine.name}"
										ariaLabel="Rename {row.machine.name}"
										onclick={() => startRename(row.machine)}
									>
										<Icon name="rename" size={14} />
									</Keycap>
									<Keycap
										type="button"
										size="sm"
										variant="ghost"
										title="Unpair {row.machine.name}"
										ariaLabel="Unpair {row.machine.name}"
										onclick={() => (unpairingTarget = row.machine)}
									>
										<Icon name="ban" size={14} />
									</Keycap>
								</div>
							</td>
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
			unit="machines"
			onPage={(p) => (page = p)}
		/>
	{:else}
		<EmptyState icon="machine" title="No machines match" text="Adjust the filters, or pair a new machine." />
	{/if}
</Panel>

<Dialog bind:open={pairing} title="Pair a machine" width={540}>
	<p class="muted">
		Run this on the machine you want to expose. It dials out to the relay — nothing new is exposed
		on your network.
	</p>
	<pre class="code mono">weave pair relay.wvr.run</pre>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (pairing = false)}>Done</Keycap>
	</svelte:fragment>
</Dialog>

<Dialog
	open={renamingTarget !== null}
	title="Rename machine"
	width={460}
	onClose={() => (renamingTarget = null)}
>
	<div class="stack form">
		<label for="mach-rename-list">New name</label>
		<input
			id="mach-rename-list"
			class="control mono"
			bind:value={renameValue}
			on:input={() => (renameValue = renameValue.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 15))}
		/>
	</div>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (renamingTarget = null)}>Cancel</Keycap>
		<Keycap
			type="button"
			variant="primary"
			disabled={!/^[a-z0-9]{1,15}$/.test(renameValue)}
			onclick={confirmRename}
		>
			Rename
		</Keycap>
	</svelte:fragment>
</Dialog>

<Dialog
	open={kickingTarget !== null}
	title="Kick {kickingTarget?.name ?? 'machine'}?"
	width={460}
	onClose={() => (kickingTarget = null)}
>
	<p class="muted">
		Immediately disconnects <strong>{kickingTarget?.name}</strong> and drops all of its open
		service tunnels. This action is irreversible from the web UI — to reconnect, the user must run
		<code class="mono">weave start</code> on the machine itself.
	</p>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (kickingTarget = null)}>
			No, keep connected
		</Keycap>
		<Keycap type="button" variant="danger" onclick={confirmKick}>
			<Icon name="power" size={14} /> Yes, kick machine
		</Keycap>
	</svelte:fragment>
</Dialog>

<ConfirmDeleteDialog
	open={unpairingTarget !== null}
	title="Unpair {unpairingTarget?.name ?? 'machine'}?"
	expected={unpairingTarget?.name ?? ''}
	confirmLabel="Unpair machine"
	cancelLabel="Keep machine"
	onClose={() => (unpairingTarget = null)}
	onConfirm={confirmUnpair}
>
	<p>
		Revokes <strong>{unpairingTarget?.name}</strong>'s key immediately. Its live tunnel drops and its
		hostnames stop serving.
	</p>
</ConfirmDeleteDialog>

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
		width: 240px;
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

	.svc-pills {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
	}

	.svc-pill {
		padding: 1px 7px;
		border: 1px solid var(--tw-line-soft);
		border-radius: 999px;
		font-size: 11px;
		color: var(--tw-muted);
		border-style: dashed;
	}

	.svc-pill.open {
		border-style: solid;
		border-color: var(--tw-online);
		color: var(--tw-online);
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

	.code {
		margin: 12px 0 0;
		padding: 12px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-raised);
		font-size: 13px;
	}

	.form {
		margin-top: 0;
	}
</style>
