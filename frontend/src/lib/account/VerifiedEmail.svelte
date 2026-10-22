<script lang="ts">
	/**
	 * The verified address above a new-password field: a real readonly
	 * `autocomplete="username"` control, so password managers associate the new
	 * password with the account.
	 */
	interface Props {
		email: string;
	}

	let { email }: Props = $props();
</script>

<div class="field">
	<label for="username">Email</label>
	<input
		id="username"
		name="username"
		type="email"
		autocomplete="username"
		readonly
		value={email}
	/>
	<p class="hint"><span class="check" aria-hidden="true">✓</span> Verified email</p>
</div>

<style lang="scss">
	.check {
		color: var(--tw-success);
		font-weight: 700;
	}
</style>
