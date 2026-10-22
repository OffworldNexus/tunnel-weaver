<script lang="ts">
	/** A friendly empty state. */
	import type { Snippet } from 'svelte';

	import Icon from '#lib/ui/Icon.svelte';
	import type { IconName } from '#lib/ui/icons';

	interface Props {
		icon?: IconName;
		title?: string;
		text?: string;
		children?: Snippet;
	}

	let { icon = 'inbox', title = 'Nothing here', text = '', children }: Props = $props();
</script>

<div class="empty">
	<span class="empty__icon"><Icon name={icon} size={26} /></span>
	<p class="empty__title">{title}</p>
	{#if text}<p class="empty__text">{text}</p>{/if}
	{@render children?.()}
</div>

<style lang="scss">
	.empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 8px;
		padding: 44px 20px;
		text-align: center;
		color: var(--tw-muted);
	}

	.empty__icon {
		display: grid;
		place-items: center;
		width: 52px;
		height: 52px;
		border: 1.5px dashed var(--tw-border);
		border-radius: 999px;
		color: var(--tw-accent);
	}

	.empty__title {
		font-family: var(--tw-heading);
		font-size: 16px;
		font-weight: 700;
		color: var(--tw-text);
	}

	.empty__text {
		max-width: 46ch;
		font-size: 14px;
	}
</style>
