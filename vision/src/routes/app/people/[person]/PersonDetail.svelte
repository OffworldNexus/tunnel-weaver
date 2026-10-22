<script lang="ts">
	/**
	 * The user overview — seen natively by a regular user on `/app`, and also when
	 * an org admin or super admin drills into `/app/people/[person]`.
	 */
	import Badge from '#lib/console/Badge.svelte';
	import BanDialog from '#lib/console/BanDialog.svelte';
	import BandwidthChart from '#lib/console/BandwidthChart.svelte';
	import ConfirmDeleteDialog from '#lib/console/ConfirmDeleteDialog.svelte';
	import Dialog from '#lib/console/Dialog.svelte';
	import EmptyState from '#lib/console/EmptyState.svelte';
	import HealthDot from '#lib/console/HealthDot.svelte';
	import MiniBar from '#lib/console/MiniBar.svelte';
	import Pagination from '#lib/console/Pagination.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import Reputation from '#lib/console/Reputation.svelte';
	import Spark from '#lib/console/Spark.svelte';
	import StackedBars from '#lib/console/StackedBars.svelte';
	import { setMeta } from '#lib/console/meta';
	import { paginate } from '#lib/console/paginate';
	import { accountColor } from '#lib/console/palette';
	import { externalSeries, hourlyBytes, projectedBytes, projectedRequests } from '#lib/console/series';
	import { notify } from '#lib/account/notices';
	import { bytes, count, date, timeAgo } from '#lib/mock/format';
	import {
		banPersonWithNote,
		current,
		deletePerson,
		healthOf,
		kickMachine,
		machines,
		orgById,
		people,
		reinstatePerson,
		renameMachine,
		selectPerson,
		unpairMachine,
		updatePerson
	} from '#lib/mock/store';
	import type { Machine } from '#lib/mock/types';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	export let id: string;

	let q = '';
	let page = 1;
	const SIZE = 8;

	let editing = false;
	let editName = '';
	let editEmail = '';
	let deleting = false;
	let suspending = false;
	let pairing = false;

	let renamingTarget: Machine | null = null;
	let renameValue = '';
	let kickingTarget: Machine | null = null;
	let unpairingTarget: Machine | null = null;

	$: person = $people.find((p) => p.id === id);
	$: org = person ? orgById(person.orgId) : undefined;
	$: isSelf = person?.id === $current?.person.id;
	$: canModerate = $current?.role === 'org_admin' || $current?.role === 'super_admin';

	$: if (person && !isSelf) {
		selectPerson(person.id);
	}

	$: if (person) {
		setMeta({
			title: isSelf ? 'Overview' : person.name,
			subtitle: isSelf ? 'Your machines, tunnels and bandwidth.' : `${person.email} · ${org?.name ?? ''}`,
			crumbs: isSelf
				? [{ label: 'Overview' }]
				: [
						...(org ? [{ label: org.name, href: '/app/org' }] : []),
						{ label: 'Users', href: '/app/org/users' },
						{ label: person.name }
					]
		});
	}

	$: theirMachines = $machines.filter((m) => m.personId === id);
	$: allServices = theirMachines.flatMap((m) => m.services);

	$: composition = [
		{
			label: 'Machines',
			active: theirMachines.filter((m) => m.online).length,
			total: theirMachines.length
		},
		{
			label: 'Tunnels',
			active: allServices.filter((s) => s.tunnel === 'open').length,
			total: allServices.length
		}
	];

	$: bw30 = projectedBytes(theirMachines, 'both');
	$: out30 = projectedBytes(theirMachines, 'out');
	$: in30 = projectedBytes(theirMachines, 'in');
	$: req30 = projectedRequests(theirMachines);

	$: rows = theirMachines
		.filter((m) => {
			const hay = `${m.name} ${m.hostname} ${m.os} ${m.services.map((s) => s.name).join(' ')}`.toLowerCase();
			return q === '' || hay.includes(q.toLowerCase());
		})
		.map((machine) => {
			const openServices = machine.services.filter((s) => s.tunnel === 'open');
			const scores = machine.services.map((s) => s.reputation);
			return {
				machine,
				health: healthOf(machine),
				tunnelsOpen: openServices.length,
				tunnelsTotal: machine.services.length,
				requestsHour: machine.services.reduce((a, s) => a + s.requestsHour, 0),
				bandwidthHour: hourlyBytes([machine], 'bytesIn') + hourlyBytes([machine], 'bytesOut'),
				bandwidth30d: projectedBytes([machine], 'both'),
				spark: externalSeries([machine]),
				reputation: scores.length ? Math.min(...scores) : 100
			};
		});

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

	function startEdit() {
		if (!person) {
			return;
		}
		editName = person.name;
		editEmail = person.email;
		editing = true;
	}

	function saveEdit() {
		if (!person) {
			return;
		}
		updatePerson(person.id, { name: editName, email: editEmail });
		editing = false;
		notify('success', 'User updated.');
	}

	function confirmSuspend(note: string) {
		if (!person) {
			return;
		}
		banPersonWithNote(person.id, note);
		suspending = false;
		notify('error', `${person.name} banned — all tunnels frozen and raw samples purged.`);
	}

	function confirmDelete() {
		if (!person) {
			return;
		}
		deletePerson(person.id);
		deleting = false;
		notify('success', 'User removed and machines unpaired.');
		void goto('/app/org/users');
	}

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
			`Disconnected ${kickingTarget.name}. The user must reconnect from their machine.`
		);
		kickingTarget = null;
	}
</script>

{#if !person}
	<Panel><EmptyState icon="users" title="User not found" text="They may have been removed." /></Panel>
{:else}
	{#if !isSelf && canModerate}
		<div class="mod-bar">
			<div class="mod-bar__meta">
				<Badge variant={accountColor(person.status)} dot>{person.status}</Badge>
				<span class="mono muted">slug: {person.slug}</span>
				<span class="muted">· Joined {date(person.createdAt)} · last seen {timeAgo(person.lastSeenAt)}</span>
			</div>
			<div class="mod-bar__actions">
				<Keycap type="button" size="sm" variant="key" onclick={startEdit}>
					<Icon name="rename" size={15} /> Edit
				</Keycap>
				{#if person.status === 'suspended'}
					<Keycap
						type="button"
						size="sm"
						variant="key"
						onclick={() => {
							reinstatePerson(person.id);
							notify('success', `${person.name} reinstated.`);
						}}
					>
						<Icon name="check" size={15} /> Reinstate
					</Keycap>
				{:else}
					<Keycap type="button" size="sm" variant="danger" onclick={() => (suspending = true)}>
						<Icon name="ban" size={15} /> Suspend
					</Keycap>
				{/if}
				<Keycap
					type="button"
					size="sm"
					variant="ghost"
					ariaLabel="Delete user"
					onclick={() => (deleting = true)}
				>
					<Icon name="trash" size={15} />
				</Keycap>
			</div>
		</div>
	{/if}

	{#if person.status === 'suspended'}
		<Panel title="Why banned" subtitle="Banned {person.bannedAt ? date(person.bannedAt) : 'recently'} · all tunnels frozen (403)">
			<div class="why-banned">
				<div class="why-banned__note">
					<span class="why-banned__label">Administrator annotation</span>
					<p class="why-banned__text">
						{person.banReason || 'Suspended by administrator after abuse review.'}
					</p>
				</div>
				{#if person.bannedSummary}
					<div class="why-banned__proof">
						<span class="why-banned__label">Retained proof summary (raw samples purged)</span>
						<p class="why-banned__summary mono">{person.bannedSummary}</p>
					</div>
				{/if}
			</div>
		</Panel>
	{/if}

	<div class="grid grid--wide">
		<Panel
			title="Machines & tunnels"
			subtitle={isSelf ? 'Online machines and open service tunnels' : `Active share for ${person.name}`}
		>
			<StackedBars groups={composition} />
		</Panel>

		<Panel title="Last 30 days" subtitle="Projected from the current rate">
			<dl class="counters">
				<div>
					<dt>Bandwidth</dt>
					<dd class="mono">{bytes(bw30)}</dd>
					<span class="counters__sub">{bytes(out30)} out · {bytes(in30)} in</span>
				</div>
				<div>
					<dt>Requests</dt>
					<dd class="mono">{count(req30)}</dd>
					<span class="counters__sub">{count(Math.round(req30 / 30))} per day</span>
				</div>
			</dl>
		</Panel>
	</div>

	<BandwidthChart
		machines={theirMachines}
		title="Real-time bandwidth"
		subtitle="All machines"
		height={250}
	/>

	<Panel flush title="Machines" subtitle="{rows.length} paired · click a row to inspect services, graphs and live logs">
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
				<input class="searchbox__input" type="search" placeholder="Filter by machine, hostname or service" bind:value={q} />
			</label>
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
												title="Kick {row.machine.name} (disconnects its live tunnel)"
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
			<EmptyState icon="machine" title="No machines match" />
		{/if}
	</Panel>
{/if}

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
		<label for="mach-rename">New name</label>
		<input
			id="mach-rename"
			class="control mono"
			bind:value={renameValue}
			on:input={() => (renameValue = renameValue.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 15))}
		/>
		<p class="hint">
			Lowercase letters and digits, up to 15 characters. Hostnames update immediately to
			<code class="mono">{person?.slug ?? 'user'}-{renameValue || 'machine'}-&lt;service&gt;.wvr.run</code>.
		</p>
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
	<div class="alert">
		<Icon name="power" size={18} />
		<p>
			Immediately disconnects <strong>{kickingTarget?.name}</strong> and drops all of its open
			service tunnels. This is irreversible from the web UI — to reconnect, the user must run
			<code class="mono">weave start</code> on the machine itself.
		</p>
	</div>
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

<Dialog bind:open={editing} title="Edit user" width={460}>
	<div class="stack form">
		<div class="stack">
			<label for="edit-name">Name</label>
			<input id="edit-name" class="control" bind:value={editName} />
		</div>
		<div class="stack">
			<label for="edit-email">Email</label>
			<input id="edit-email" class="control" type="email" bind:value={editEmail} />
		</div>
	</div>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (editing = false)}>Cancel</Keycap>
		<Keycap type="button" variant="primary" onclick={saveEdit}>Save</Keycap>
	</svelte:fragment>
</Dialog>

<BanDialog
	bind:open={suspending}
	title="Ban {person?.name}?"
	confirmLabel="Ban user & freeze tunnels"
	defaultNote={person ? `Administrative suspension of ${person.name} (${person.email}).` : ''}
	onConfirm={confirmSuspend}
>
	<p>
		Suspension is immediate: every tunnel <strong>{person?.name}</strong> owns is frozen and all
		hostnames stop serving. Your annotation and any proof summary are kept on the user page while
		raw offending samples are purged.
	</p>
</BanDialog>

<ConfirmDeleteDialog
	bind:open={deleting}
	title="Remove {person?.name}?"
	expected={person?.name ?? ''}
	confirmLabel="Remove user"
	cancelLabel="Keep user"
	onConfirm={confirmDelete}
>
	<p>
		This unpairs every machine <strong>{person?.name}</strong> owns and deletes the account. It
		cannot be undone.
	</p>
</ConfirmDeleteDialog>

<style lang="scss">
	.mod-bar {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		padding-bottom: 14px;
		border-bottom: 1.5px solid var(--tw-border);
		font-size: 13px;
	}

	.mod-bar__meta {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 10px;
	}

	.mod-bar__actions {
		display: flex;
		flex-wrap: wrap;
		gap: 8px;
	}

	.why-banned {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.why-banned__note,
	.why-banned__proof {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.why-banned__label {
		font-size: 11px;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--tw-danger);
	}

	.why-banned__text {
		font-size: 14px;
		line-height: 1.55;
		color: var(--tw-text);
	}

	.why-banned__summary {
		padding: 8px 10px;
		border: 1px solid var(--tw-danger);
		background: color-mix(in srgb, var(--tw-danger) 10%, transparent);
		color: var(--tw-danger);
		font-size: 12px;
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

	.alert {
		display: flex;
		gap: 12px;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.55;
	}

	.alert :global(svg) {
		color: var(--tw-danger);
		flex: none;
	}
</style>
