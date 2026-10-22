<script lang="ts">
	/** Fleet pages are for super admins only. */
	import { current } from '#lib/mock/store';
	import { goto } from '$app/navigation';

	let denied = false;
	$: if ($current && $current.role !== 'super_admin' && !denied) {
		denied = true;
		void goto('/app');
	}
</script>

{#if $current?.role === 'super_admin'}
	<slot />
{:else}
	<p class="denied">You do not have access to fleet administration.</p>
{/if}

<style lang="scss">
	.denied {
		padding: 40px 20px;
		text-align: center;
		color: var(--tw-muted);
	}
</style>
