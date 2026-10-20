<script lang="ts">
	/** Full user CRUD for the active organisation. */
	import Avatar from '#lib/console/Avatar.svelte';
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
	import { accountColor } from '#lib/console/palette';
	import { externalSeries, hourlyBytes, projectedBytes } from '#lib/console/series';
	import { notify } from '#lib/account/notices';
	import { bytes, count, timeAgo } from '#lib/mock/format';
	import {
		activeOrg,
		banPersonWithNote,
		createPerson,
		deletePerson,
		machines,
		people,
		reinstatePerson,
		selectPerson
	} from '#lib/mock/store';
	import type { Person } from '#lib/mock/types';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	let q = '';
	let statusFilter = 'all';
	let inviting = false;
	let newName = '';
	let newEmail = '';
	let banningTarget: Person | null = null;
	let deletingTarget: Person | null = null;
	let page = 1;
	const SIZE = 10;

	$: org = $activeOrg;
	$: if (org) {
		setMeta({
			title: 'Users',
			subtitle: `Create, inspect and moderate users in ${org.name}.`,
			crumbs: [{ label: org.name, href: '/app/org' }, { label: 'Users' }]
		});
	}

	$: members = $people.filter((p) => p.orgId === org?.id && p.role === 'user');
	$: rows = members
		.filter((p) => {
			const hay = `${p.name} ${p.email} ${p.slug}`.toLowerCase();
			return (
				(q === '' || hay.includes(q.toLowerCase())) &&
				(statusFilter === 'all' || p.status === statusFilter)
			);
		})
		.map((p) => {
			const ms = $machines.filter((m) => m.personId === p.id);
			return {
				person: p,
				machinesActive: ms.filter((m) => m.online).length,
				machinesTotal: ms.length,
				requests: ms.reduce((a, m) => a + m.services.reduce((x, s) => x + s.requestsHour, 0), 0),
				bandwidthHour: hourlyBytes(ms, 'bytesIn') + hourlyBytes(ms, 'bytesOut'),
				bandwidth30d: projectedBytes(ms, 'both'),
				spark: externalSeries(ms)
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

	function openUser(userId: string) {
		selectPerson(userId);
		void goto(`/app/people/${userId}`);
	}

	function invite() {
		if (!org || !newName || !newEmail) {
			return;
		}
		createPerson({
			orgId: org.id,
			name: newName,
			email: newEmail,
			slug: newName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 15) || 'user',
			role: 'user'
		});
		newName = '';
		newEmail = '';
		inviting = false;
		notify('success', 'Invitation sent. The user can pair machines once they accept.');
	}
</script>

<Panel flush title="Users in {org?.name ?? 'organisation'}" subtitle="{rows.length} of {members.length} shown">
	<svelte:fragment slot="actions">
		<Keycap type="button" size="sm" variant="primary" onclick={() => (inviting = true)}>
			<Icon name="plus" size={15} /> Invite user
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
			<option value="invited">Invited</option>
			<option value="suspended">Suspended</option>
		</select>
		<span class="toolbar__spacer"></span>
	</div>

	{#if paged.total}
		<div class="table-wrap">
			<table class="table">
				<thead>
					<tr>
						<th>User</th>
						<th>Status</th>
						<th>Machines</th>
						<th>External bandwidth · 1h</th>
						<th class="right">Bandwidth · 30d</th>
						<th>Reputation</th>
						<th>Last seen</th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					{#each paged.items as row (row.person.id)}
						<!-- svelte-ignore a11y_no_noninteractive_element_interactions, a11y_click_events_have_key_events -->
						<tr
							class="row-link"
							class:suspended={row.person.status === 'suspended'}
							role="link"
							tabindex="0"
							on:click={() => openUser(row.person.id)}
							on:keydown={(e) => {
								if (e.key === 'Enter' || e.key === ' ') {
									e.preventDefault();
									openUser(row.person.id);
								}
							}}
						>
							<td>
								<span class="member">
									<Avatar name={row.person.name} size={30} />
									<span class="col">
										<span class="member__name">{row.person.name}</span>
										<span class="member__email mono">{row.person.email}</span>
									</span>
								</span>
							</td>
							<td><Badge variant={accountColor(row.person.status)} dot>{row.person.status}</Badge></td>
							<td><MiniBar active={row.machinesActive} total={row.machinesTotal} /></td>
							<td>
								<span class="bw-cell">
									<span class="spark"><Spark data={row.spark} color="var(--tw-c1)" height={26} /></span>
									<span class="bw-cell__val mono">{bytes(row.bandwidthHour)}</span>
								</span>
							</td>
							<td class="right mono">{bytes(row.bandwidth30d)}</td>
							<td><Reputation score={row.person.reputation} compact /></td>
							<td class="muted">{timeAgo(row.person.lastSeenAt)}</td>
							<td class="right" on:click|stopPropagation>
								<div class="row-actions">
									{#if row.person.status === 'suspended'}
										<Keycap
											type="button"
											size="sm"
											variant="key"
											onclick={() => {
												reinstatePerson(row.person.id);
												notify('success', 'User reinstated.');
											}}
										>
											Reinstate
										</Keycap>
									{:else}
										<Keycap
											type="button"
											size="sm"
											variant="danger"
											onclick={() => (banningTarget = row.person)}
										>
											Suspend
										</Keycap>
									{/if}
									<Keycap
										type="button"
										size="sm"
										variant="ghost"
										ariaLabel="Remove {row.person.name}"
										onclick={() => (deletingTarget = row.person)}
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
			unit="users"
			onPage={(p) => (page = p)}
		/>
	{:else}
		<EmptyState icon="users" title="No users match" text="Adjust the filters or invite someone." />
	{/if}
</Panel>

<Dialog bind:open={inviting} title="Invite a user" width={460}>
	<div class="stack form">
		<div class="stack">
			<label for="invite-name">Full name</label>
			<input id="invite-name" class="control" bind:value={newName} placeholder="Jordan Rivera" />
		</div>
		<div class="stack">
			<label for="invite-email">Email</label>
			<input id="invite-email" class="control" type="email" bind:value={newEmail} placeholder="jordan@example.com" />
		</div>
	</div>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (inviting = false)}>Cancel</Keycap>
		<Keycap type="button" variant="primary" disabled={!newName || !newEmail} onclick={invite}>
			Send invitation
		</Keycap>
	</svelte:fragment>
</Dialog>

<BanDialog
	open={banningTarget !== null}
	title="Ban {banningTarget?.name ?? 'user'}?"
	confirmLabel="Ban user & freeze tunnels"
	defaultNote={banningTarget ? `Suspended by organisation administrator (${banningTarget.email}).` : ''}
	onClose={() => (banningTarget = null)}
	onConfirm={(note) => {
		if (banningTarget) {
			banPersonWithNote(banningTarget.id, note);
			banningTarget = null;
			notify('error', 'User banned — tunnels frozen and raw samples purged.');
		}
	}}
>
	<p>
		Immediately suspends <strong>{banningTarget?.name}</strong> and freezes all of their tunnels.
		Your annotation and any proof tally are stored on the user record while raw offending samples
		are purged.
	</p>
</BanDialog>

<ConfirmDeleteDialog
	open={deletingTarget !== null}
	title="Remove {deletingTarget?.name ?? 'user'}?"
	expected={deletingTarget?.name ?? ''}
	confirmLabel="Remove user"
	onClose={() => (deletingTarget = null)}
	onConfirm={() => {
		if (deletingTarget) {
			deletePerson(deletingTarget.id);
			deletingTarget = null;
			notify('success', 'User removed and their machines unpaired.');
		}
	}}
>
	<p>
		Unpairs every machine owned by <strong>{deletingTarget?.name}</strong> and deletes the account.
		This cannot be undone.
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

	tr.suspended {
		opacity: 0.72;
	}

	.member {
		display: inline-flex;
		align-items: center;
		gap: 10px;
	}

	.member__name {
		font-weight: 700;
	}

	.member__email {
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

	.form {
		margin-top: 0;
	}
</style>
