<script lang="ts">
	/**
	 * Multi-select dropdown for filtering a machine's bandwidth graph and live
	 * logs across any subset of services (handles machines with many services).
	 */
	import type { Service } from '#lib/mock/types';
	import Icon from '#lib/ui/Icon.svelte';

	export let services: Service[] = [];
	/** Empty array means "all services selected". */
	export let selectedIds: string[] = [];
	export let onChange: (ids: string[]) => void = () => {};

	let open = false;
	let filter = '';
	let box: HTMLDivElement;

	$: allSelected = selectedIds.length === 0 || selectedIds.length === services.length;
	$: activeSet = new Set(allSelected ? services.map((s) => s.id) : selectedIds);

	$: filteredServices = services.filter((s) => {
		const hay = `${s.name} ${s.hostname} ${s.target}`.toLowerCase();
		return filter === '' || hay.includes(filter.toLowerCase());
	});

	$: summaryText = allSelected
		? `All services (${services.length})`
		: selectedIds.length === 1
			? (services.find((s) => s.id === selectedIds[0])?.name ?? '1 service')
			: `${selectedIds.length} of ${services.length} services`;

	function toggleService(id: string) {
		const next = new Set(activeSet);
		if (next.has(id)) {
			next.delete(id);
		} else {
			next.add(id);
		}
		if (next.size === 0 || next.size === services.length) {
			selectedIds = [];
		} else {
			selectedIds = [...next];
		}
		onChange(selectedIds);
	}

	function selectAll() {
		selectedIds = [];
		onChange(selectedIds);
	}

	function selectOnly(id: string) {
		selectedIds = [id];
		onChange(selectedIds);
	}

	function onWindowClick(event: MouseEvent) {
		if (box && !box.contains(event.target as Node)) {
			open = false;
		}
	}
</script>

<svelte:window on:click={onWindowClick} />

<div class="msel" bind:this={box}>
	<button
		type="button"
		class="msel__trigger"
		aria-expanded={open}
		on:click={() => (open = !open)}
	>
		<Icon name="network" size={14} />
		<span class="msel__label">Services:</span>
		<strong class="msel__val mono">{summaryText}</strong>
		<Icon name="chevron-down" size={14} />
	</button>

	{#if open}
		<div class="msel__popover">
			<div class="msel__top">
				<input
					type="search"
					class="control control--sm"
					placeholder="Filter services…"
					bind:value={filter}
				/>
				<button type="button" class="link-action" on:click={selectAll}>
					All ({services.length})
				</button>
			</div>

			<ul class="msel__list">
				{#each filteredServices as svc (svc.id)}
					{@const checked = activeSet.has(svc.id)}
					<li class="msel__row">
						<button
							type="button"
							class="msel__option"
							class:is-checked={checked}
							on:click={() => toggleService(svc.id)}
						>
							<span class="msel__box" aria-hidden="true">{checked ? '▪' : ''}</span>
							<span class="msel__name mono">{svc.name}</span>
							<span class="msel__host mono">{svc.hostname}</span>
						</button>
						<button
							type="button"
							class="msel__only mono"
							on:click={() => selectOnly(svc.id)}
							title="Select only {svc.name}"
						>
							only
						</button>
					</li>
				{/each}
			</ul>
		</div>
	{/if}
</div>

<style lang="scss">
	@use 'mixins' as *;

	.msel {
		position: relative;
		display: inline-block;
	}

	.msel__trigger {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		height: 32px;
		padding: 0 11px;
		border: 1.5px solid var(--tw-border);
		background: var(--tw-deck);
		color: var(--tw-text);
		font: 600 12px/1 var(--tw-sans);
		cursor: pointer;
	}

	.msel__trigger:hover,
	.msel__trigger[aria-expanded='true'] {
		border-color: var(--tw-accent);
	}

	.msel__label {
		color: var(--tw-muted);
		text-transform: uppercase;
		font-family: var(--tw-mono);
		font-size: 11px;
		letter-spacing: 0.04em;
	}

	.msel__val {
		font-size: 12px;
	}

	.msel__popover {
		@include cut-panel(12px, var(--tw-well), var(--tw-border), 1.5px);
		position: absolute;
		top: calc(100% + 6px);
		left: 0;
		z-index: 45;
		width: min(360px, 88vw);
		padding: 10px;
		box-shadow: var(--tw-shadow);
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.msel__top {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.msel__top input {
		flex: 1;
	}

	.msel__list {
		list-style: none;
		margin: 0;
		padding: 0;
		max-height: 220px;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.msel__row {
		display: flex;
		align-items: center;
		gap: 4px;
	}

	.msel__option {
		flex: 1;
		display: flex;
		align-items: center;
		gap: 8px;
		min-width: 0;
		padding: 6px 8px;
		border: 0;
		background: none;
		color: var(--tw-muted);
		text-align: left;
		cursor: pointer;
	}

	.msel__option:hover {
		background: color-mix(in srgb, var(--tw-text) 7%, transparent);
		color: var(--tw-text);
	}

	.msel__option.is-checked {
		color: var(--tw-text);
	}

	.msel__box {
		display: inline-grid;
		place-items: center;
		width: 14px;
		height: 14px;
		flex: none;
		border: 1.5px solid var(--tw-border);
		background: var(--tw-deck);
		color: var(--tw-accent);
		font-size: 11px;
		line-height: 1;
	}

	.msel__option.is-checked .msel__box {
		border-color: var(--tw-accent);
	}

	.msel__name {
		font-size: 12px;
		font-weight: 700;
	}

	.msel__host {
		font-size: 11px;
		color: var(--tw-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.msel__only {
		border: 1px solid var(--tw-line-soft);
		background: var(--tw-raised);
		color: var(--tw-muted);
		padding: 2px 6px;
		font-size: 10px;
		text-transform: uppercase;
		cursor: pointer;
	}

	.msel__only:hover {
		border-color: var(--tw-accent);
		color: var(--tw-accent);
	}
</style>
