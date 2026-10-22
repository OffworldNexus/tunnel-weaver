<script lang="ts">
	/**
	 * Global Super-Admin Review Board: lists organisations that have suspicious
	 * users, scored by how quickly and responsibly they handle them. From here
	 * the super admin can either dive into an organisation's review page or ban
	 * the organisation outright.
	 */
	import BanDialog from '#lib/console/BanDialog.svelte';
	import EmptyState from '#lib/console/EmptyState.svelte';
	import Pagination from '#lib/console/Pagination.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import Reputation from '#lib/console/Reputation.svelte';
	import { setMeta } from '#lib/console/meta';
	import { paginate } from '#lib/console/paginate';
	import { notify } from '#lib/account/notices';
	import { orgs, people, review, selectOrg, suspendOrg } from '#lib/mock/store';
	import type { Org } from '#lib/mock/types';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	setMeta({
		title: 'Review queue',
		subtitle:
			'Organisations with suspicious users, ranked by how quickly they resolve abuse.',
		crumbs: [{ label: 'Review queue' }]
	});

	let page = 1;
	const SIZE = 8;
	let banningOrg: Org | null = null;

	function formatResponseTime(mins: number): string {
		if (mins < 60) {
			return `${mins}m median`;
		}
		const h = Math.floor(mins / 60);
		const m = mins % 60;
		return m > 0 ? `${h}h ${m}m median` : `${h}h median`;
	}

	$: rows = $orgs
		.filter((org) => org.status !== 'suspended')
		.map((org) => {
			const pendingItems = $review.filter((r) => r.orgId === org.id && r.verdict === 'pending');
			const offendingUserIds = new Set(pendingItems.map((r) => r.personId));
			const offendingUsers = $people.filter((p) => offendingUserIds.has(p.id));
			const totalInfractions = pendingItems.reduce(
				(sum, r) => sum + r.infractions.reduce((a, inf) => a + inf.count, 0),
				0
			);
			const fingerprints = pendingItems.reduce((sum, r) => sum + r.distinctFingerprints, 0);
			return {
				org,
				pendingServices: pendingItems.length,
				offendingUsers,
				totalInfractions,
				fingerprints
			};
		})
		.filter((row) => row.pendingServices > 0)
		.sort((a, b) => a.org.reputation - b.org.reputation);

	$: paged = paginate(rows, page, SIZE);

	function diveIntoOrg(orgId: string) {
		selectOrg(orgId);
		void goto('/app/org/review');
	}

	function confirmBanOrg(note: string) {
		if (!banningOrg) {
			return;
		}
		suspendOrg(banningOrg.id, note);
		notify('error', `${banningOrg.name} banned — all member tunnels frozen and raw samples purged.`);
		banningOrg = null;
	}
</script>

<Panel
	flush
	title="Organisations with unresolved abuse"
	subtitle="{rows.length} organisation{rows.length === 1 ? '' : 's'} with pending infractions · scored by response speed"
>
	{#if paged.total}
		<div class="table-wrap">
			<table class="table">
				<thead>
					<tr>
						<th>Organisation</th>
						<th>Suspicious users</th>
						<th class="right">Detected infractions</th>
						<th class="right">Visitor fingerprints</th>
						<th>Response speed</th>
						<th>Moderation score</th>
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
							on:click={() => diveIntoOrg(row.org.id)}
							on:keydown={(e) => {
								if (e.key === 'Enter' || e.key === ' ') {
									e.preventDefault();
									diveIntoOrg(row.org.id);
								}
							}}
						>
							<td>
								<span class="cell-name">{row.org.name}</span>
								<span class="cell-sub mono">{row.org.slug}</span>
							</td>
							<td>
								<span class="mono">
									<strong>{row.offendingUsers.length}</strong>
									user{row.offendingUsers.length === 1 ? '' : 's'}
								</span>
								<span class="cell-sub">
									{row.offendingUsers.map((u) => u.name).join(', ')}
								</span>
							</td>
							<td class="right mono">
								<span class="infraction-count">{row.totalInfractions}</span>
							</td>
							<td class="right mono">{row.fingerprints}</td>
							<td>
								<span
									class="mono speed"
									class:slow={row.org.meanResponseMinutes > 120}
								>
									{formatResponseTime(row.org.meanResponseMinutes)}
								</span>
							</td>
							<td>
								<Reputation score={row.org.reputation} showLabel />
							</td>
							<td class="right" on:click|stopPropagation>
								<div class="row-actions">
									<Keycap
										type="button"
										size="sm"
										variant="key"
										onclick={() => diveIntoOrg(row.org.id)}
									>
										Review org →
									</Keycap>
									<Keycap
										type="button"
										size="sm"
										variant="danger"
										onclick={() => (banningOrg = row.org)}
									>
										<Icon name="ban" size={14} /> Ban org
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
		<EmptyState
			icon="shield"
			title="No organisations have unresolved abuse"
			text="Every flagged user across the fleet has been handled."
		/>
	{/if}
</Panel>

<BanDialog
	open={banningOrg !== null}
	title="Ban {banningOrg?.name ?? 'organisation'}?"
	confirmLabel="Ban organisation"
	defaultNote={banningOrg
		? `Unresolved abuse across member tunnels (moderation score ${banningOrg.reputation}/100, median response ${banningOrg.meanResponseMinutes}m).`
		: ''}
	onClose={() => (banningOrg = null)}
	onConfirm={confirmBanOrg}
>
	<p>
		Suspends <strong>{banningOrg?.name}</strong> and freezes every tunnel owned by every member
		immediately. Your annotation and the non-content proof summary are saved on the organisation
		record while raw offending payload samples are purged.
	</p>
</BanDialog>

<style lang="scss">
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

	.infraction-count {
		color: var(--tw-danger);
		font-weight: 700;
	}

	.speed.slow {
		color: var(--tw-danger);
		font-weight: 700;
	}
</style>
