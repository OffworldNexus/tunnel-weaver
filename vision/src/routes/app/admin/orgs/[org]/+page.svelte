<script lang="ts">
	/** Entering an organisation selects it in the sidebar tree and opens its native overview. */
	import { selectOrg } from '#lib/mock/store';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { onMount } from 'svelte';

	onMount(() => {
		const id = page.params.org ?? '';
		if (id) {
			selectOrg(id);
		}
		void goto('/app/org', { replaceState: true });
	});
</script>

<p class="muted">Opening organisation…</p>
