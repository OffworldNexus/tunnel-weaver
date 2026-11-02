<script lang="ts">
	/**
	 * The Microsoft logo: four squares, the official colours.
	 *
	 * A dedicated component rather than an entry in `Icon`, whose icons are single
	 * `currentColor` paths — this mark is four separate fills and must never be
	 * recoloured to the text colour.
	 */
	interface Props {
		size?: number;
	}
	let { size = 14 }: Props = $props();
</script>

<svg class="ms" viewBox="0 0 23 23" width={size} height={size} aria-hidden="true" focusable="false">
	<rect x="1" y="1" width="10" height="10" fill="#f25022" />
	<rect x="12" y="1" width="10" height="10" fill="#7fba00" />
	<rect x="1" y="12" width="10" height="10" fill="#00a4ef" />
	<rect x="12" y="12" width="10" height="10" fill="#ffb900" />
</svg>

<style lang="scss">
	.ms {
		display: block;
		flex: none;
	}
</style>
