<script lang="ts">
	/** Small stroke icons for the landing page. Inline SVG, currentColor only. */
	export let name: 'plug' | 'lock' | 'globe' | 'shield' | 'battery' = 'plug';
</script>

<svg
	class="icon"
	viewBox="0 0 24 24"
	width="24"
	height="24"
	fill="none"
	stroke="currentColor"
	stroke-width="1.7"
	stroke-linecap="round"
	stroke-linejoin="round"
	aria-hidden="true"
	focusable="false"
>
	{#if name === 'plug'}
		<path d="M9 2v6M15 2v6M6 8h12v3a6 6 0 0 1-12 0V8Z" />
		<path d="M12 17v5" />
	{:else if name === 'lock'}
		<rect x="4" y="10" width="16" height="11" rx="2" />
		<path d="M8 10V7a4 4 0 0 1 8 0v3" />
	{:else if name === 'globe'}
		<circle cx="12" cy="12" r="9" />
		<path d="M3 12h18" />
		<path d="M12 3c2.5 2.6 3.8 5.7 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.7-3.8-9S9.5 5.6 12 3Z" />
	{:else if name === 'battery'}
		<rect x="2" y="7" width="16.5" height="10" rx="2.5" />
		<path d="M22.5 10.5v3" />
		<path d="M11.5 9 9.6 12.4h3.2L10.9 15.6" />
	{:else}
		<path d="M12 3 5 6v5c0 4.4 3 8.4 7 10 4-1.6 7-5.6 7-10V6l-7-3Z" />
		<path d="m9 12 2 2 4-4" />
	{/if}
</svg>
