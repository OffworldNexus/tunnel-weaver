<script lang="ts">
	/**
	 * A compact inline active-vs-total bar for table cells: a 72×8 stacked track
	 * beside the `active / total` ratio, fixed-width so columns stay aligned.
	 */
	export let active: number;
	export let total: number;
	export let color = 'var(--tw-c2)';

	$: share = total > 0 ? Math.min(100, Math.max(0, (active / total) * 100)) : 0;
</script>

<span class="minibar" style="--bar-color: {color}" title="{active} active of {total}">
	<span class="minibar__track" aria-hidden="true">
		<span class="minibar__active" style="width: {share}%"></span>
		<span class="minibar__rest" style="width: {100 - share}%"></span>
	</span>
	<span class="minibar__ratio mono">
		<strong>{active}</strong><span class="minibar__sep">/</span>{total}
	</span>
</span>

<style lang="scss">
	.minibar {
		display: inline-grid;
		grid-template-columns: 72px 46px;
		align-items: center;
		gap: 10px;
	}

	.minibar__track {
		display: flex;
		width: 72px;
		height: 8px;
		border-radius: 2px;
		overflow: hidden;
		background: color-mix(in srgb, var(--tw-text) 8%, transparent);
	}

	.minibar__active {
		height: 100%;
		background: var(--bar-color);
	}

	.minibar__rest {
		height: 100%;
		background: repeating-linear-gradient(
			-45deg,
			color-mix(in srgb, var(--tw-text) 24%, transparent) 0 3px,
			color-mix(in srgb, var(--tw-text) 10%, transparent) 3px 6px
		);
	}

	.minibar__ratio {
		font-size: 13px;
		color: var(--tw-muted);
		text-align: right;
		white-space: nowrap;
	}

	.minibar__ratio strong {
		color: var(--tw-text);
	}

	.minibar__sep {
		margin: 0 1px;
		opacity: 0.65;
	}
</style>
