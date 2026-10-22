<script lang="ts">
	/** An initials avatar. Deterministic tint from the name. */
	export let name: string;
	export let size = 34;

	$: initials = name
		.split(/\s+/)
		.filter(Boolean)
		.slice(0, 2)
		.map((w) => w[0]?.toUpperCase() ?? '')
		.join('');

	$: hue = [...name].reduce((h, ch) => (h * 31 + ch.charCodeAt(0)) % 360, 0);
</script>

<span
	class="avatar"
	style="--size: {size}px; --hue: {hue}"
	role="img"
	aria-label={name}
>{initials}</span
>

<style lang="scss">
	.avatar {
		display: inline-grid;
		place-items: center;
		width: var(--size, 34px);
		height: var(--size, 34px);
		flex: none;
		border-radius: 999px;
		border: 1.5px solid var(--tw-border);
		background: color-mix(in oklab, var(--tw-confirm) 45%, var(--tw-well));
		color: var(--tw-text);
		font-family: var(--tw-heading);
		font-size: calc(var(--size, 34px) * 0.38);
		font-weight: 700;
		letter-spacing: 0.02em;
	}
</style>
