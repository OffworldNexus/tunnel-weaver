<script lang="ts">
	/** Security overview: what the account signs in with. */
	import { me } from '#lib/app/me.svelte';
	import { setMeta } from '#lib/console/meta.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Panel from '#lib/ui/Panel.svelte';
	import { resolve } from '$app/paths';

	setMeta({
		title: 'Security',
		subtitle: 'Choose how you sign in. Protect your account.',
		crumbs: [{ label: 'Security' }]
	});
</script>

<Panel
	title="Password"
	subtitle="Your password signs you in and authorises changes to the account."
>
	{#snippet actions()}
		<Keycap href={resolve('/app/security/password')} variant="key" size="sm">
			<Icon name="lock" size={14} /> Change password
		</Keycap>
	{/snippet}

	{#if me.value?.has_password}
		<p class="state"><Icon name="check" size={16} /> Password is set</p>
	{:else}
		<p class="state">No password is set</p>
	{/if}
</Panel>

<style lang="scss">
	.state {
		display: flex;
		align-items: center;
		gap: 8px;
		margin: 0;
		color: var(--tw-muted);
	}

	.state :global(svg) {
		color: var(--tw-online);
	}
</style>
