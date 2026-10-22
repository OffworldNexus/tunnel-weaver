<script lang="ts">
	/**
	 * The organisation overview — seen natively by the org admin, and also when
	 * a super admin selects an organisation from the fleet list.
	 */
	import Avatar from '#lib/console/Avatar.svelte';
	import Badge from '#lib/console/Badge.svelte';
	import BandwidthChart from '#lib/console/BandwidthChart.svelte';
	import Dialog from '#lib/console/Dialog.svelte';
	import EmptyState from '#lib/console/EmptyState.svelte';
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
	import { bytes, count, date } from '#lib/mock/format';
	import {
		activeOrg,
		createPerson,
		current,
		machines,
		people,
		reinstateOrg,
		review,
		selectPerson
	} from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	let q = '';
	let userFilter = 'all';
	let page = 1;
	const SIZE = 8;

	let inviting = false;
	let newName = '';
	let newEmail = '';

	$: org = $activeOrg;
	$: if (org) {
		setMeta({
			title: org.name,
			subtitle: `Organisation overview · ${org.slug}`,
			crumbs: [
				...($current?.role === 'super_admin'
					? [{ label: 'Organisations', href: '/app/admin/orgs' }]
					: []),
				{ label: org.name }
			]
		});
	}

	$: users = $people.filter((p) => p.orgId === org?.id && p.role === 'user');
	$: userIds = new Set(users.map((u) => u.id));
	$: orgMachines = $machines.filter((m) => userIds.has(m.personId));
	$: chartMachines =
		userFilter === 'all' ? orgMachines : orgMachines.filter((m) => m.personId === userFilter);
	$: pending = $review.filter((r) => r.orgId === org?.id && r.verdict === 'pending');

	$: composition = [
		{
			label: 'Users',
			active: users.filter((u) => u.status === 'active').length,
			total: users.length
		},
		{
			label: 'Machines',
			active: orgMachines.filter((m) => m.online).length,
			total: orgMachines.length
		}
	];

	$: bw30 = projectedBytes(orgMachines, 'both');
	$: out30 = projectedBytes(orgMachines, 'out');
	$: in30 = projectedBytes(orgMachines, 'in');
	$: req30 = projectedRequests(orgMachines);

	$: rows = users
		.map((user) => {
			const ms = orgMachines.filter((m) => m.personId === user.id);
			return {
				user,
				machinesActive: ms.filter((m) => m.online).length,
				machinesTotal: ms.length,
				requestsHour: ms.reduce((a, m) => a + m.services.reduce((x, s) => x + s.requestsHour, 0), 0),
				bandwidthHour: hourlyBytes(ms, 'bytesIn') + hourlyBytes(ms, 'bytesOut'),
				bandwidth30d: projectedBytes(ms, 'both'),
				spark: externalSeries(ms)
			};
		})
		.filter((row) => {
			const hay = `${row.user.name} ${row.user.email} ${row.user.slug}`.toLowerCase();
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
		notify('success', 'Invitation sent.');
	}
</script>

{#if !org}
	<Panel>
		<EmptyState
			icon="building"
			title="No organisation selected"
			text="Pick an organisation from the fleet overview to inspect it."
		/>
	</Panel>
{:else}
	{#if org.status === 'suspended'}
		<Panel
			title="Why banned"
			subtitle="Banned {org.bannedAt ? date(org.bannedAt) : 'recently'} · all member accounts and tunnels frozen"
		>
			<svelte:fragment slot="actions">
				{#if $current?.role === 'super_admin'}
					<Keycap
						type="button"
						size="sm"
						variant="key"
						onclick={() => {
							reinstateOrg(org.id);
							notify('success', `${org.name} reinstated.`);
						}}
					>
						Reinstate organisation
					</Keycap>
				{/if}
			</svelte:fragment>
			<div class="why-banned">
				<div class="why-banned__note">
					<span class="why-banned__label">Super-admin annotation</span>
					<p class="why-banned__text">
						{org.banReason || 'Suspended by super admin for unresolved abuse.'}
					</p>
				</div>
				{#if org.bannedSummary}
					<div class="why-banned__proof">
						<span class="why-banned__label">Retained proof summary (raw samples purged)</span>
						<p class="why-banned__summary mono">{org.bannedSummary}</p>
					</div>
				{/if}
			</div>
		</Panel>
	{/if}

	{#if pending.length}
		<a class="review-banner" href="/app/org/review">
			<span class="review-banner__icon"><Icon name="alert" size={20} /></span>
			<span class="review-banner__text">
				<strong>{pending.length} service{pending.length === 1 ? ' needs' : 's need'} review in {org.name}.</strong>
				The abuse ranker kept a sample of suspicious HTTP queries for inspection.
			</span>
			<span class="review-banner__cta">Open the review queue →</span>
		</a>
	{/if}

	<div class="grid grid--wide">
		<Panel title="Organisation composition" subtitle="Active vs total in {org.name}">
			<StackedBars groups={composition} />
		</Panel>

		<Panel title="Last 30 days" subtitle="Projected from {org.name}'s current rate">
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

	<div class="bw-block">
		<div class="bw-filter">
			<label class="bw-filter__label">
				<Icon name="users" size={15} />
				<span>Scope:</span>
				<select class="control control--sm" bind:value={userFilter} aria-label="Filter bandwidth by user">
					<option value="all">All users in {org.name}</option>
					{#each users as u (u.id)}
						<option value={u.id}>{u.name}</option>
					{/each}
				</select>
			</label>
		</div>
		<BandwidthChart
			machines={chartMachines}
			title="Real-time bandwidth"
			subtitle={userFilter === 'all'
				? `${org.name} · all users`
				: `${users.find((u) => u.id === userFilter)?.name ?? ''}`}
			height={250}
		/>
	</div>

	<Panel flush title="Users" subtitle="{rows.length} in {org.name} · click a row to enter">
		<svelte:fragment slot="actions">
			<Keycap type="button" size="sm" variant="primary" onclick={() => (inviting = true)}>
				<Icon name="plus" size={15} /> Invite user
			</Keycap>
			<Keycap size="sm" variant="key" href="/app/org/users">Manage all</Keycap>
		</svelte:fragment>

		<div class="toolbar">
			<label class="searchbox">
				<Icon name="search" size={16} />
				<input class="searchbox__input" type="search" placeholder="Filter users by name or email" bind:value={q} />
			</label>
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
							<th class="right">Req/h</th>
							<th>External bandwidth · 1h</th>
							<th class="right">Bandwidth · 30d</th>
							<th>Reputation</th>
							<th></th>
						</tr>
					</thead>
					<tbody>
						{#each paged.items as row (row.user.id)}
							<!-- svelte-ignore a11y_no_noninteractive_element_interactions, a11y_click_events_have_key_events -->
							<tr
								class="row-link"
								role="link"
								tabindex="0"
								on:click={() => openUser(row.user.id)}
								on:keydown={(e) => {
									if (e.key === 'Enter' || e.key === ' ') {
										e.preventDefault();
										openUser(row.user.id);
									}
								}}
							>
								<td>
									<span class="member">
										<Avatar name={row.user.name} size={30} />
										<span class="col">
											<span class="cell-name">{row.user.name}</span>
											<span class="cell-sub mono">{row.user.email}</span>
										</span>
									</span>
								</td>
								<td>
									<Badge variant={accountColor(row.user.status)} dot>{row.user.status}</Badge>
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
								<td><Reputation score={row.user.reputation} compact /></td>
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
				unit="users"
				onPage={(p) => (page = p)}
			/>
		{:else}
			<EmptyState icon="users" title="No users match" />
		{/if}
	</Panel>
{/if}

<Dialog bind:open={inviting} title="Invite a user to {org?.name ?? ''}" width={460}>
	<div class="stack form">
		<div class="stack">
			<label for="inv-name">Full name</label>
			<input id="inv-name" class="control" bind:value={newName} placeholder="Jordan Rivera" />
		</div>
		<div class="stack">
			<label for="inv-email">Email</label>
			<input id="inv-email" class="control" type="email" bind:value={newEmail} placeholder="jordan@example.com" />
		</div>
	</div>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (inviting = false)}>Cancel</Keycap>
		<Keycap type="button" variant="primary" disabled={!newName || !newEmail} onclick={invite}>
			Send invitation
		</Keycap>
	</svelte:fragment>
</Dialog>

<style lang="scss">
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

	.bw-block {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.bw-filter {
		display: flex;
		justify-content: flex-end;
	}

	.bw-filter__label {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		font-size: 13px;
		color: var(--tw-muted);
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

	.member {
		display: inline-flex;
		align-items: center;
		gap: 10px;
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

	.form {
		margin-top: 0;
	}
</style>
