<script lang="ts">
	import type { Snippet } from 'svelte';

	/** A landing section shell: heading, lede and the card list that follows. */
	interface Props {
		id: string;
		title: string;
		lede: string;
		/** `<ol>` for an ordered walkthrough, `<ul>` for a set. */
		listTag?: 'ol' | 'ul';
		/** Minimum card width before the grid wraps. */
		cardsMin?: string;
		children?: Snippet;
	}

	let { id, title, lede, listTag = 'ul', cardsMin = '240px', children }: Props = $props();
</script>

<section class="section" aria-labelledby={id}>
	<h2 {id} class="section-title">{title}</h2>
	<p class="section-lede">{lede}</p>
	<svelte:element this={listTag} class="cards" style={`--cards-min:${cardsMin}`}>
		{@render children?.()}
	</svelte:element>
</section>

<style lang="scss">
	.section {
		width: 100%;
		max-width: 1120px;
		padding: clamp(44px, 8vh, 88px) clamp(20px, 5vw, 40px);
	}

	.section-title {
		font-size: clamp(24px, 3vw, 34px);
		line-height: 1.1;
		font-weight: 700;
	}

	.section-lede {
		margin-top: 10px;
		margin-bottom: clamp(22px, 4vh, 38px);
		color: var(--tw-muted);
		max-width: 60ch;
	}

	.cards {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(min(100%, var(--cards-min, 240px)), 1fr));
		gap: clamp(14px, 2vw, 22px);
	}
</style>
