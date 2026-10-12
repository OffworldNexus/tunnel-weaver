<script lang="ts">
	/**
	 * A live password-strength meter, shared by the set-password and reset pages.
	 *
	 * Purely decorative guidance: it is `aria-hidden` because the accessible
	 * signal is the relay's enforced policy and the field's own error message.
	 */
	import { passwordStrength } from '#lib/account/strength';

	/** The password to score; an empty value renders an empty meter. */
	export let value: string;

	$: strength = passwordStrength(value);
</script>

<div class="strength" aria-hidden="true">
	<span class="strength__track">
		<span class="strength__fill" data-level={strength.level} style={`width:${strength.pct}%`}></span>
	</span>
	<span class="strength__label">{strength.label}</span>
</div>

<style lang="scss">
	.strength {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.strength__track {
		flex: 1;
		height: 6px;
		border-radius: 999px;
		background: var(--tw-well);
		border: 1.5px solid var(--tw-border);
		overflow: hidden;
	}

	.strength__fill {
		display: block;
		height: 100%;
		background: var(--tw-success);
		transition: width 140ms ease;
	}

	.strength__fill[data-level='weak'] {
		background: var(--tw-danger);
	}

	.strength__label {
		min-width: 3.6rem;
		text-align: right;
		color: var(--tw-muted);
		font-size: 14px;
	}

	@media (prefers-reduced-motion: reduce) {
		.strength__fill {
			transition: none;
		}
	}
</style>
