<script lang="ts">
	/**
	 * The "pair a machine" instructions, shared by the machines list and the
	 * overview: the command to run, with the relay host the account plane
	 * reports, and a link to the setup docs.
	 */
	import { config } from '#lib/account/config';
	import { REPO_URL } from '#lib/app/links';
	import Dialog from '#lib/ui/Dialog.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';

	export let open = false;
	export let onClose: (() => void) | undefined = undefined;
</script>

<Dialog bind:open title="Pair a machine" width={560} {onClose}>
	<p class="muted">
		Run this on the machine you want to expose. It dials out to the relay — nothing new is exposed
		on your network.
	</p>
	<pre class="code mono">weave pair {$config?.relay_host ?? '<relay-host>'}</pre>
	<Keycap
		type="button"
		variant="ghost"
		size="sm"
		href={REPO_URL}
		target="_blank"
		rel="noopener noreferrer"
	>
		<Icon name="github" size={15} /> Setup instructions
	</Keycap>

	{#snippet footer()}
		<Keycap type="button" variant="key" onclick={() => (open = false)}>Done</Keycap>
	{/snippet}
</Dialog>

<style lang="scss">
	.code {
		margin: 12px 0;
		padding: 12px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-raised);
		font-size: 13px;
	}
</style>
