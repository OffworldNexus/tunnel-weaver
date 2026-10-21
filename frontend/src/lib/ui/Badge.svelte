<script lang="ts">
	/** A small status pill. The dot form is used in dense tables. */
	export let variant: 'neutral' | 'ok' | 'warn' | 'danger' | 'info' | 'accent' | 'muted' =
		'neutral';
	export let dot = false;
	export let title = '';
</script>

<span class="badge badge--{variant}" {title}>
	{#if dot}<span class="badge__dot" aria-hidden="true"></span>{/if}
	<slot />
</span>

<style lang="scss">
	.badge {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 2px 8px;
		border: 1.5px solid currentColor;
		border-radius: 999px;
		font-size: 12px;
		font-weight: 700;
		line-height: 1.6;
		white-space: nowrap;
	}

	.badge__dot {
		width: 7px;
		height: 7px;
		border-radius: 999px;
		background: currentColor;
		flex: none;
	}

	.badge--neutral {
		color: var(--tw-muted);
	}
	.badge--muted {
		color: var(--tw-offline);
		border-style: dashed;
	}
	.badge--ok {
		color: var(--tw-online);
	}
	.badge--warn {
		color: var(--tw-idle);
	}
	.badge--danger {
		color: var(--tw-danger);
	}
	.badge--info {
		color: var(--tw-info);
	}
	.badge--accent {
		color: var(--tw-accent);
	}
</style>
