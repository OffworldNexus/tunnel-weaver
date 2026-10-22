<script lang="ts">
	interface Props {
		value: string;
		error?: string;
		disabled?: boolean;
	}

	let { value = $bindable(), error = undefined, disabled = false }: Props = $props();
</script>

<div class="field">
	<label for="email">Email</label>
	<input
		id="email"
		name="email"
		type="email"
		autocomplete="username"
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
