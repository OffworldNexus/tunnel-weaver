<script lang="ts">
	/**
	 * Organisation Review Page: paginated list of offending users in the active
	 * organisation. Clicking a user opens their Offense Page with visitor
	 * fingerprint metrics, infraction category counts, and sampled requests
	 * (including labelled image infractions).
	 */
	import Avatar from '#lib/console/Avatar.svelte';
	import EmptyState from '#lib/console/EmptyState.svelte';
	import Pagination from '#lib/console/Pagination.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import Reputation from '#lib/console/Reputation.svelte';
	import { setMeta } from '#lib/console/meta';
	import { paginate } from '#lib/console/paginate';
	import { timeAgo } from '#lib/mock/format';
	import { activeOrg, machines, people, selectPerson, visibleReview } from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	let page = 1;
	const SIZE = 8;

	$: org = $activeOrg;
	$: setMeta({
		title: 'Review queue',
		subtitle: org
			? `Offending users flagged in ${org.name}. Click a user to inspect their offense report.`
			: 'Offending users flagged in this organisation.',
		crumbs: [...(org ? [{ label: org.name, href: '/app/org' }] : []), { label: 'Review queue' }]
	});

	$: pending = $visibleReview.filter((r) => r.verdict === 'pending');

	$: rows = [...new Set(pending.map((r) => r.personId))]
		.map((personId) => {
			const user = $people.find((p) => p.id === personId);
			if (!user) {
				return null;
			}
			const userItems = pending.filter((r) => r.personId === personId);
			const serviceNames = userItems.map((item) => {
				const m = $machines.find((mach) => mach.id === item.machineId);
				const s = m?.services.find((svc) => svc.id === item.serviceId);
				return s?.hostname ?? item.serviceId;
			});
			const fingerprints = userItems.reduce((a, r) => a + r.distinctFingerprints, 0);
			const tallies = new Map<string, number>();
			for (const item of userItems) {
				for (const inf of item.infractions) {
					tallies.set(inf.category, (tallies.get(inf.category) ?? 0) + inf.count);
				}
			}
			const totalInfractions = [...tallies.values()].reduce((a, b) => a + b, 0);
			const oldest = [...userItems].sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0]
				?.createdAt ?? '';
			return {
				user,
				serviceNames,
				fingerprints,
				tallies: [...tallies.entries()],
				totalInfractions,
				oldest
			};
		})
		.filter((r): r is NonNullable<typeof r> => r !== null)
		.sort((a, b) => a.user.reputation - b.user.reputation);

	$: paged = paginate(rows, page, SIZE);

	function openOffense(personId: string) {
		selectPerson(personId);
		void goto(`/app/org/review/${personId}`);
	}
</script>

<Panel
	flush
	title="Offending users in {org?.name ?? 'organisation'}"
	subtitle="{rows.length} user{rows.length === 1 ? '' : 's'} awaiting a decision · click a row to inspect metrics & sampled requests"
>
	{#if paged.total}
		<div class="table-wrap">
			<table class="table">
				<thead>
					<tr>
						<th>User</th>
						<th>Flagged services</th>
						<th class="right">Visitor fingerprints</th>
						<th>Detected infractions</th>
						<th>Reputation</th>
						<th>Flagged</th>
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
							on:click={() => openOffense(row.user.id)}
							on:keydown={(e) => {
								if (e.key === 'Enter' || e.key === ' ') {
									e.preventDefault();
									openOffense(row.user.id);
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
								<div class="svc-list">
									{#each row.serviceNames as host (host)}
										<span class="svc-tag mono">{host}</span>
									{/each}
								</div>
							</td>
							<td class="right mono">
								<strong>{row.fingerprints}</strong>
							</td>
							<td>
								<div class="inf-tags">
									{#each row.tallies.slice(0, 2) as [cat, cnt] (cat)}
										<span class="inf-tag mono">{cat.split('·')[0].trim()} · {cnt}</span>
									{/each}
									{#if row.tallies.length > 2}
										<span class="muted mono">+{row.tallies.length - 2} more</span>
									{/if}
								</div>
							</td>
							<td>
								<Reputation score={row.user.reputation} compact />
							</td>
							<td class="muted">{timeAgo(row.oldest)}</td>
							<td class="right" on:click|stopPropagation>
								<Keycap
									type="button"
									size="sm"
									variant="key"
									onclick={() => openOffense(row.user.id)}
								>
									Inspect offense <Icon name="arrow-right" size={14} />
								</Keycap>
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
			unit="offending users"
			onPage={(p) => (page = p)}
		/>
	{:else}
		<EmptyState
			icon="shield"
			title="No offending users in {org?.name ?? 'this organisation'}"
			text="Every service in this organisation is currently within the reputation threshold."
		/>
	{/if}
</Panel>

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

	.svc-list,
	.inf-tags {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
	}

	.svc-tag {
		padding: 1px 6px;
		border: 1px solid var(--tw-line-soft);
		font-size: 11px;
		color: var(--tw-muted);
	}

	.inf-tag {
		padding: 1px 7px;
		border: 1px solid var(--tw-danger);
		background: color-mix(in srgb, var(--tw-danger) 12%, transparent);
		color: var(--tw-danger);
		font-size: 11px;
		font-weight: 700;
	}
</style>
