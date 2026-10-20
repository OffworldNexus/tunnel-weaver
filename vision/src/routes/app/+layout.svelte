<script lang="ts">
	/**
	 * The signed-in console shell. It guards the session (redirecting a
	 * signed-out visitor to sign-in) and mounts the chrome once for every
	 * `/app` route.
	 */
	import Shell from '#lib/console/Shell.svelte';
	import Inspect from '#lib/console/Inspect.svelte';
	import { meta } from '#lib/console/meta';
	import { current, startLive } from '#lib/mock/store';
	import { goto } from '$app/navigation';

	let redirected = false;

	$: if (!$current && !redirected) {
		redirected = true;
		void goto('/sign-in');
	}
	$: if ($current) {
		redirected = false;
	}

	// Keep the mock world moving for as long as the console is mounted.
	startLive();

	$: title = $meta.title;
	$: subtitle = $meta.subtitle;
	$: crumbs = $meta.crumbs;
</script>

{#if $current}
	<Shell {title} {subtitle} {crumbs}>
		<slot />
	</Shell>
	<Inspect />
{:else}
	<p class="booting">Loading the console…</p>
{/if}

<style lang="scss">
	.booting {
		padding: 48px 20px;
		text-align: center;
		color: var(--tw-muted);
	}
</style>
