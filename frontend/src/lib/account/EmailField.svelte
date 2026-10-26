<script lang="ts">
	interface Props {
		value: string;
		error?: string;
		disabled?: boolean;
		/**
		 * Whether to invite the browser to offer a passkey in this field's
		 * autofill (WVR-163).
		 *
		 * The `webauthn` token in `autocomplete` is what the conditional-UI
		 * ceremony looks for: without it the browser has nowhere to put the
		 * passkey it discovered. Only the sign-in page asks for it — everywhere
		 * else the field is just an address.
		 */
		passkeys?: boolean;
	}

	let {
		value = $bindable(),
		error = undefined,
		disabled = false,
		passkeys = false
	}: Props = $props();
</script>

<div class="field">
	<label for="email">Email</label>
	<input
		id="email"
		name="email"
		type="email"
		autocomplete={passkeys ? 'username webauthn' : 'username'}
		inputmode="email"
		autocapitalize="none"
		spellcheck="false"
		placeholder="you@example.com"
		bind:value
		{disabled}
		aria-invalid={error ? 'true' : undefined}
	/>
	{#if error}<p class="field__error" aria-live="polite">{error}</p>{/if}
</div>
