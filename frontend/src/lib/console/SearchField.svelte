<script lang="ts">
	/**
	 * The top-bar search. The console has one searchable collection — the
	 * signed-in person's machines — so the field drives that list: the first
	 * keystroke lands on the list and the results update as you type, the query
	 * itself living in the shared `searchQuery` store.
	 */
	import { searchQuery } from '#lib/console/search';
	import Icon from '#lib/ui/Icon.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';

	let input: HTMLInputElement;

	async function onInput() {
		if (!page.url.pathname.startsWith('/app/machines')) {
			// Carry the query over, so the list opens on what was typed.
			const query = $searchQuery;
			const suffix = query ? `?q=${encodeURIComponent(query)}` : '';
			// eslint-disable-next-line svelte/no-navigation-without-resolve -- the path is the resolved list route
			await goto(resolve('/app/machines') + suffix);
		}
		// The list is the search surface; keep the caret in the field so the
		// keystrokes after the navigation are not swallowed.
		input?.focus();
	}

	function onKey(event: KeyboardEvent) {
		if (event.key === 'Enter') {
			event.preventDefault();
			void onInput();
		}
		if (event.key === 'Escape') {
			searchQuery.set('');
			input?.blur();
		}
	}

	function onWindowKey(event: KeyboardEvent) {
		if (event.ctrlKey && event.key.toLowerCase() === 'k') {
			event.preventDefault();
			input?.focus();
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
		placeholder="Search machines…"
		bind:value={$searchQuery}
		on:input={onInput}
		on:keydown={onKey}
		autocomplete="off"
		spellcheck="false"
		aria-label="Search machines"
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
		<kbd class="lookup__kbd">Ctrl K</kbd>
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
		white-space: nowrap;
	}

	@media (max-width: 720px) {
		.lookup {
			width: 100%;
		}
	}
</style>
