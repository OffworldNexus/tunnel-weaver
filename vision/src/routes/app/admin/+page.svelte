<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	onMount(() => {
		void goto('/app/admin/orgs');
	});
</script>

<p class="muted">Opening organisations…</p>
