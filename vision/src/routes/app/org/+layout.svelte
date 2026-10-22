<script lang="ts">
	/** Organisation pages are for org admins (and super admins). */
	import { current } from '#lib/mock/store';
	import { goto } from '$app/navigation';

	let denied = false;
	$: if ($current && $current.role === 'user' && !denied) {
		denied = true;
		void goto('/app');
	}
</script>

{#if $current && $current.role !== 'user'}
	<slot />
{:else}
	<p class="denied">You do not have access to organisation management.</p>
{/if}

<style lang="scss">
	.denied {
		padding: 40px 20px;
		text-align: center;
		color: var(--tw-muted);
	}
</style>
