<script lang="ts">
	/** A client-side pager: a count, page numbers and prev/next using `Keycap`. */
	import { pageWindow } from '#lib/app/paginate';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';

	interface Props {
		page?: number;
		pageCount?: number;
		total?: number;
		from?: number;
		to?: number;
		unit?: string;
		onPage?: (page: number) => void;
		/** Drop the pager's own chrome, for use inside a panel footer. */
		bare?: boolean;
	}

	let {
		page = 1,
		pageCount = 1,
		total = 0,
		from = 0,
		to = 0,
		unit = 'rows',
		onPage = () => {},
		bare = false
	}: Props = $props();

	const buttons = $derived(pageWindow(page, pageCount));
</script>

{#if pageCount > 1 || total > 0}
	<nav class="pager" class:bare aria-label="Pagination">
		<span class="pager__count">
			{#if total === 0}
				No {unit}
			{:else}
				<span class="mono">{from}–{to}</span> of <span class="mono">{total}</span> {unit}
			{/if}
		</span>
		{#if pageCount > 1}
			<div class="pager__pages">
				<span class="pager__prev">
					<Keycap
						type="button"
						size="sm"
						variant="key"
						disabled={page <= 1}
						ariaLabel="Previous page"
						onclick={() => onPage(page - 1)}
					>
						<Icon name="chevron-right" size={14} />
					</Keycap>
				</span>
				{#each buttons as b, i (i)}
					{#if b === 'gap'}
						<span class="pager__gap">…</span>
					{:else}
						<Keycap
							type="button"
							size="sm"
							variant={b === page ? 'primary' : 'key'}
							onclick={() => onPage(b)}
						>
							<span class="mono">{b}</span>
						</Keycap>
					{/if}
				{/each}
				<Keycap
					type="button"
					size="sm"
					variant="key"
					disabled={page >= pageCount}
					ariaLabel="Next page"
					onclick={() => onPage(page + 1)}
				>
					<Icon name="chevron-right" size={14} />
				</Keycap>
			</div>
		{/if}
	</nav>
{/if}

<style lang="scss">
	.pager {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 10px;
		padding: 10px 14px;
		border-top: 1.5px solid var(--tw-border);
		font-size: 13px;
		color: var(--tw-muted);
	}

	/* Inside a panel footer the separator and padding already exist. */
	.pager.bare {
		padding: 0;
		border-top: 0;
	}

	.pager__pages {
		display: flex;
		align-items: center;
		gap: 6px;
	}

	/* The chevron points right; flip it for the previous button. */
	.pager__prev :global(svg) {
		transform: rotate(180deg);
	}

	.pager__gap {
		padding: 0 4px;
		color: var(--tw-muted);
	}
</style>
