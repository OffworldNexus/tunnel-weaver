<script lang="ts">
	export let value: string;
	export let error: string | undefined = undefined;
	export let disabled = false;
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
