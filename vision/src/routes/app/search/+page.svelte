<script lang="ts">
	/** The full-screen search surface, opened from the header field. */
	import EmptyState from '#lib/console/EmptyState.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Pagination from '#lib/console/Pagination.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import { setMeta } from '#lib/console/meta';
	import { current } from '#lib/mock/store';
	import { paginate } from '#lib/console/paginate';
	import {
		FILTERS,
		KIND_LABEL,
		KIND_ORDER,
		searchQuery,
		searchResults,
		type Kind
	} from '#lib/console/search';

	setMeta({
		title: 'Search',
		subtitle: 'Machines, services, people and organisations you can see.',
		crumbs: [{ label: 'Search' }]
	});

	const SIZE = 10;

	let kinds = new Set<Kind>(KIND_ORDER);
	let page = 1;

	$: results = $searchResults;
	$: counts = KIND_ORDER.map((kind) => ({
		kind,
		label: KIND_LABEL[kind],
		count: results.filter((r) => r.kind === kind).length
	}));
	$: filtered = results.filter((r) => kinds.has(r.kind));

	const filterKey = () => `${$searchQuery}|${[...kinds].sort().join(',')}`;
	let lastKey = '';
	$: {
		const key = filterKey();
		if (key !== lastKey) {
			lastKey = key;
			page = 1;
		}
	}

	$: paged = paginate(filtered, page, SIZE);
	$: groups = KIND_ORDER.map((kind) => ({
		kind,
		label: KIND_LABEL[kind],
		items: paged.items.filter((r) => r.kind === kind)
	})).filter((g) => g.items.length > 0);

	const examples = ['machine:lab', 'service:grafana', 'org:"helio"', 'user:sam', 'host:sams-'];

	function toggle(kind: Kind) {
		const next = new Set(kinds);
		if (next.has(kind)) {
			next.delete(kind);
		} else {
			next.add(kind);
		}
		kinds = next;
	}
</script>

<div class="searchbox">
	<span class="searchbox__icon"><Icon name="search" size={18} /></span>
	<input
		class="searchbox__input"
		type="text"
		bind:value={$searchQuery}
		placeholder='Search…  machine:lab   org:"acme"   service:grafana   user:sam'
		autocomplete="off"
		spellcheck="false"
		aria-label="Search"
	/>
	{#if $searchQuery}
		<button class="searchbox__clear" type="button" aria-label="Clear" on:click={() => searchQuery.set('')}>
			<Icon name="close" size={16} />
		</button>
	{/if}
</div>

{#if !$searchQuery.trim()}
	<div class="layout">
		<Panel title="Search the fleet" subtitle="Scoped to what your role can see">
			<p class="help">
				Start typing to search. Mix free text with field filters — everything is matched
				case-insensitively and only over the parts you have access to.
			</p>
			<ul class="filters">
				{#each FILTERS as f (f.key)}
					<li><code class="mono">{f.key}:</code> <span>{f.help}</span></li>
				{/each}
			</ul>
			<p class="help">Examples:</p>
			<div class="chips">
				{#each examples as ex (ex)}
					<button class="chip" type="button" on:click={() => searchQuery.set(ex)}>{ex}</button>
				{/each}
			</div>
		</Panel>
		<Panel title="Access" subtitle="What each role can reach">
			<p class="help">
				As a <strong>{$current?.role.replace('_', ' ')}</strong>, this box reaches
				{#if $current?.role === 'super_admin'}
					every organisation, member, machine and service on the relay.
				{:else if $current?.role === 'org_admin'}
					every member, machine and service in {$current?.org?.name ?? 'your organisation'}.
				{:else}
					your own machines, services and account.
				{/if}
			</p>
		</Panel>
	</div>
{:else}
	<div class="chips kinds">
		<button class="chip" class:is-on={kinds.size === KIND_ORDER.length} type="button" on:click={() => (kinds = new Set(KIND_ORDER))}>
			All <span class="chip__count">{results.length}</span>
		</button>
		{#each counts as c (c.kind)}
			<button class="chip" class:is-on={kinds.has(c.kind) && kinds.size !== KIND_ORDER.length} type="button" on:click={() => toggle(c.kind)}>
				{c.label} <span class="chip__count">{c.count}</span>
			</button>
		{/each}
	</div>

	<Panel flush title="{filtered.length} matches" subtitle="Closest first">
		{#if filtered.length === 0}
			<EmptyState
				icon="search"
				title="Nothing matches"
				text="Check the spelling, loosen a filter, or try a broader term."
			/>
		{:else}
			{#each groups as group (group.kind)}
				<p class="group">{group.label}</p>
				<ul class="results">
					{#each group.items as result (result.href)}
						<li>
							<a class="result" href={result.href}>
								<span class="result__icon"><Icon name={result.icon} size={16} /></span>
								<span class="result__text">
									<span class="result__label">{result.label}</span>
									<span class="result__sub mono">{result.sub}</span>
								</span>
								<span class="result__kind">{KIND_LABEL[result.kind].slice(0, -1).toLowerCase()}</span>
								<Icon name="arrow-right" size={15} />
							</a>
						</li>
					{/each}
				</ul>
			{/each}
		{/if}
		<Pagination
			page={paged.page}
			pageCount={paged.pageCount}
			total={paged.total}
			from={paged.from}
			to={paged.to}
			unit="matches"
			onPage={(p) => (page = p)}
		/>
	</Panel>
{/if}

<style lang="scss">
	.searchbox {
		display: flex;
		align-items: center;
		gap: 10px;
		height: 52px;
		padding: 0 16px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
		color: var(--tw-muted);
	}

	.searchbox:focus-within {
		border-color: var(--tw-accent);
	}

	.searchbox__input {
		flex: 1 1 auto;
		min-width: 0;
		border: 0;
		background: none;
		color: var(--tw-text);
		font: 400 16px/1 var(--tw-sans);
		outline: none;
	}

	.searchbox__clear {
		display: grid;
		place-items: center;
		width: 26px;
		height: 26px;
		border: 0;
		border-radius: var(--tw-radius);
		background: none;
		color: var(--tw-muted);
		cursor: pointer;
	}

	.searchbox__clear:hover {
		color: var(--tw-text);
	}

	.layout {
		display: grid;
		grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr);
		gap: 16px;
	}

	@media (max-width: 900px) {
		.layout {
			grid-template-columns: 1fr;
		}
	}

	.help {
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.6;
		margin-bottom: 12px;
	}

	.help strong {
		color: var(--tw-text);
	}

	.filters {
		list-style: none;
		margin: 0 0 14px;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 8px;
		font-size: 14px;
	}

	.filters li {
		display: flex;
		gap: 8px;
	}

	.filters code {
		color: var(--tw-accent);
		font-weight: 700;
		min-width: 84px;
	}

	.filters span {
		color: var(--tw-muted);
	}

	.kinds {
		margin-bottom: 4px;
	}

	.chip__count {
		display: inline-grid;
		place-items: center;
		min-width: 18px;
		height: 18px;
		padding: 0 5px;
		border-radius: 999px;
		background: color-mix(in srgb, var(--tw-text) 10%, transparent);
		font-family: var(--tw-mono);
		font-size: 11px;
	}

	.group {
		padding: 12px 16px 4px;
		font-size: 10px;
		font-weight: 700;
		letter-spacing: 0.1em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.results {
		list-style: none;
		margin: 0;
		padding: 0;
	}

	.result {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 10px 16px;
		border-top: 1px solid var(--tw-line-hair);
		color: var(--tw-text);
		text-decoration: none;
	}

	.result:hover {
		background: color-mix(in srgb, var(--tw-text) 5%, transparent);
		text-decoration: none;
	}

	.result__icon {
		display: grid;
		place-items: center;
		width: 28px;
		height: 28px;
		flex: none;
		border: 1.5px solid var(--tw-line-soft);
		border-radius: var(--tw-radius);
		color: var(--tw-accent);
	}

	.result__text {
		display: flex;
		flex-direction: column;
		min-width: 0;
		flex: 1 1 auto;
	}

	.result__label {
		font-weight: 700;
		font-size: 14px;
	}

	.result__sub {
		font-size: 11px;
		color: var(--tw-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.result__kind {
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		color: var(--tw-muted);
	}
</style>
