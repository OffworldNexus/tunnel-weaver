<script lang="ts">
	/**
	 * The header search field. It is the launcher for the search page: focusing
	 * it or typing immediately opens `/app/search`, and the query lives in the
	 * shared `searchQuery` store so both stay in sync.
	 */
	import Icon from '#lib/ui/Icon.svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';

	import { searchQuery } from './search';

	let input: HTMLInputElement;

	function onSearchPage(): boolean {
		return page.url.pathname.startsWith('/app/search');
	}

	async function openSearch() {
		if (!onSearchPage()) {
			await goto('/app/search');
		}
		// Focus survives the route change only if we put it back; otherwise the
		// first keystroke that opens the page would swallow the rest of the word.
		input?.focus();
	}

	function onInput() {
		void openSearch();
	}

	function onKey(event: KeyboardEvent) {
		if (event.key === 'Escape') {
			searchQuery.set('');
			input?.blur();
		}
	}

	function onWindowKey(event: KeyboardEvent) {
		if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
			event.preventDefault();
			void openSearch();
		}
	}
</script>

<svelte:window on:keydown={onWindowKey} />

<div class="lookup">
	<Icon name="search" size={16} />
	<input
		bind:this={input}
		class="lookup__input"
		type="text"
		placeholder='Search machines, services, people…  try machine:lab or org:"acme"'
		bind:value={$searchQuery}
		on:focus={openSearch}
		on:input={onInput}
		on:keydown={onKey}
		autocomplete="off"
		spellcheck="false"
		aria-label="Search machines, services and people"
	/>
	{#if $searchQuery}
		<button
			class="lookup__clear"
			type="button"
			aria-label="Clear search"
			on:click={() => {
				searchQuery.set('');
				input?.focus();
			}}
		>
			<Icon name="close" size={14} />
		</button>
	{:else}
		<kbd class="lookup__kbd">⌘K</kbd>
	{/if}
</div>

<style lang="scss">
	.lookup {
		display: flex;
		flex-direction: row;
		align-items: center;
		gap: 8px;
		height: 36px;
		width: min(420px, 42vw);
		padding: 0 10px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
		color: var(--tw-muted);
	}

	.lookup:focus-within {
		border-color: var(--tw-accent);
	}

	.lookup__input {
		flex: 1 1 auto;
		min-width: 0;
		height: 100%;
		border: 0;
		background: none;
		color: var(--tw-text);
		font: 400 14px/1 var(--tw-sans);
		outline: none;
	}

	.lookup__input::placeholder {
		color: var(--tw-muted);
	}

	.lookup__clear {
		display: grid;
		place-items: center;
		width: 22px;
		height: 22px;
		flex: none;
		border: 0;
		border-radius: var(--tw-radius);
		background: none;
		color: var(--tw-muted);
		cursor: pointer;
	}

	.lookup__clear:hover {
		color: var(--tw-text);
	}

	.lookup__kbd {
		font-family: var(--tw-mono);
		font-size: 11px;
		color: var(--tw-muted);
		border: 1px solid var(--tw-line-soft);
		border-radius: var(--tw-radius);
		padding: 1px 5px;
	}

	@media (max-width: 720px) {
		.lookup {
			width: 100%;
		}
	}
</style>
