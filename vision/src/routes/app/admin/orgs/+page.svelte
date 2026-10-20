<script lang="ts">
	/** Full organisation CRUD for the super admin, including suspended tenants. */
	import Badge from '#lib/console/Badge.svelte';
	import BanDialog from '#lib/console/BanDialog.svelte';
	import ConfirmDeleteDialog from '#lib/console/ConfirmDeleteDialog.svelte';
	import Dialog from '#lib/console/Dialog.svelte';
	import EmptyState from '#lib/console/EmptyState.svelte';
	import MiniBar from '#lib/console/MiniBar.svelte';
	import Pagination from '#lib/console/Pagination.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import Reputation from '#lib/console/Reputation.svelte';
	import Spark from '#lib/console/Spark.svelte';
	import { setMeta } from '#lib/console/meta';
	import { paginate } from '#lib/console/paginate';
	import { orgColor } from '#lib/console/palette';
	import { externalSeries, hourlyBytes, projectedBytes } from '#lib/console/series';
	import { notify } from '#lib/account/notices';
	import { bytes, count, date } from '#lib/mock/format';
	import {
		createOrg,
		deleteOrg,
		machines,
		orgs,
		people,
		reinstateOrg,
		selectOrg,
		suspendOrg
	} from '#lib/mock/store';
	import type { Org } from '#lib/mock/types';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	setMeta({
		title: 'Organisations',
		subtitle: 'Create, inspect, suspend and remove organisations.',
		crumbs: [{ label: 'Organisations' }]
	});

	let q = '';
	let statusFilter = 'all';
	let creating = false;
	let newName = '';
	let newSlug = '';
	let newContact = '';
	let banningTarget: Org | null = null;
	let deletingTarget: Org | null = null;
	let page = 1;
	const SIZE = 10;

	$: rows = $orgs
		.filter((o) => {
			const hay = `${o.name} ${o.slug} ${o.contactEmail}`.toLowerCase();
			const okQ = q === '' || hay.includes(q.toLowerCase());
			const okStatus = statusFilter === 'all' || o.status === statusFilter;
			return okQ && okStatus;
		})
		.map((org) => {
			const users = $people.filter((p) => p.orgId === org.id && p.role === 'user');
			const ids = new Set(users.map((m) => m.id));
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
		});

	const filterKey = () => `${q}|${statusFilter}`;
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

	function create() {
		if (!newName) {
			return;
		}
		createOrg({
			name: newName,
			slug: newSlug || newName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 20),
			contactEmail: newContact
		});
		newName = '';
		newSlug = '';
		newContact = '';
		creating = false;
		notify('success', 'Organisation created.');
	}
</script>

<Panel flush title="All organisations" subtitle="{rows.length} of {$orgs.length} shown">
	<svelte:fragment slot="actions">
		<Keycap type="button" size="sm" variant="primary" onclick={() => (creating = true)}>
			<Icon name="plus" size={15} /> New organisation
		</Keycap>
	</svelte:fragment>

	<div class="toolbar">
		<label class="searchbox">
			<Icon name="search" size={16} />
			<input class="searchbox__input" type="search" placeholder="Name, slug or email" bind:value={q} />
		</label>
		<select class="control control--sm" bind:value={statusFilter} aria-label="Status">
			<option value="all">Any status</option>
			<option value="active">Active</option>
			<option value="suspended">Suspended</option>
		</select>
		<span class="toolbar__spacer"></span>
	</div>

	{#if paged.total}
		<div class="table-wrap">
			<table class="table">
				<thead>
					<tr>
						<th>Organisation</th>
						<th>Status</th>
						<th>Users</th>
						<th>Machines</th>
						<th>External bandwidth · 1h</th>
						<th class="right">Bandwidth · 30d</th>
						<th>Reputation</th>
						<th>Created</th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					{#each paged.items as row (row.org.id)}
						<!-- svelte-ignore a11y_no_noninteractive_element_interactions, a11y_click_events_have_key_events -->
						<tr
							class="row-link"
							class:dim={row.org.status === 'suspended'}
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
							<td><Badge variant={orgColor(row.org.status)} dot>{row.org.status}</Badge></td>
							<td><MiniBar active={row.usersActive} total={row.usersTotal} /></td>
							<td><MiniBar active={row.machinesActive} total={row.machinesTotal} /></td>
							<td>
								<span class="bw-cell">
									<span class="spark"><Spark data={row.spark} color="var(--tw-c1)" height={26} /></span>
									<span class="bw-cell__val mono">{bytes(row.bandwidthHour)}</span>
								</span>
							</td>
							<td class="right mono">{bytes(row.bandwidth30d)}</td>
							<td><Reputation score={row.org.reputation} compact /></td>
							<td class="muted">{date(row.org.createdAt)}</td>
							<td class="right" on:click|stopPropagation>
								<div class="row-actions">
									{#if row.org.status === 'suspended'}
										<Keycap
											type="button"
											size="sm"
											variant="key"
											onclick={() => {
												reinstateOrg(row.org.id);
												notify('success', 'Organisation reinstated.');
											}}
										>
											Reinstate
										</Keycap>
									{:else}
										<Keycap
											type="button"
											size="sm"
											variant="danger"
											onclick={() => (banningTarget = row.org)}
										>
											Suspend
										</Keycap>
									{/if}
									<Keycap
										type="button"
										size="sm"
										variant="ghost"
										ariaLabel="Delete {row.org.name}"
										onclick={() => (deletingTarget = row.org)}
									>
										<Icon name="trash" size={14} />
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
			unit="organisations"
			onPage={(p) => (page = p)}
		/>
	{:else}
		<EmptyState icon="building" title="No organisations match" />
	{/if}
</Panel>

<Dialog bind:open={creating} title="New organisation" width={480}>
	<div class="stack form">
		<div class="stack">
			<label for="org-new-name">Name</label>
			<input id="org-new-name" class="control" bind:value={newName} placeholder="Acme Robotics" />
		</div>
		<div class="stack">
			<label for="org-new-slug">Slug</label>
			<input id="org-new-slug" class="control mono" bind:value={newSlug} placeholder="acme" />
		</div>
		<div class="stack">
			<label for="org-new-contact">Contact email</label>
			<input id="org-new-contact" class="control" type="email" bind:value={newContact} placeholder="ops@acme.example" />
		</div>
	</div>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (creating = false)}>Cancel</Keycap>
		<Keycap type="button" variant="primary" disabled={!newName} onclick={create}>Create</Keycap>
	</svelte:fragment>
</Dialog>

<BanDialog
	open={banningTarget !== null}
	title="Ban {banningTarget?.name ?? 'organisation'}?"
	confirmLabel="Ban organisation"
	defaultNote={banningTarget
		? `Administrative suspension of ${banningTarget.name} (score ${banningTarget.reputation}/100).`
		: ''}
	onClose={() => (banningTarget = null)}
	onConfirm={(note) => {
		if (banningTarget) {
			suspendOrg(banningTarget.id, note);
			banningTarget = null;
			notify('error', 'Organisation banned — member tunnels frozen and raw samples purged.');
		}
	}}
>
	<p>
		Suspends <strong>{banningTarget?.name}</strong> and freezes every tunnel owned by every member
		immediately. Your annotation and the proof summary are kept on the organisation page while raw
		offending samples are purged.
	</p>
</BanDialog>

<ConfirmDeleteDialog
	open={deletingTarget !== null}
	title="Delete {deletingTarget?.name ?? 'organisation'}?"
	expected={deletingTarget?.name ?? ''}
	confirmLabel="Delete organisation"
	onClose={() => (deletingTarget = null)}
	onConfirm={() => {
		if (deletingTarget) {
			deleteOrg(deletingTarget.id);
			deletingTarget = null;
			notify('success', 'Organisation deleted.');
		}
	}}
>
	<p>
		Deletes <strong>{deletingTarget?.name}</strong> along with every user, paired machine and tunnel
		inside it. This cannot be undone.
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

	tr.dim {
		opacity: 0.72;
	}

	.form {
		margin-top: 0;
	}
</style>
