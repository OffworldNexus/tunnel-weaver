<script lang="ts">
	/**
	 * The signed-in account's avatar: a deterministic bird that the relay renders
	 * from the account's email address (`bird-id`). The image belongs to the
	 * relay, so this only points at its URL — and asks for twice the display size
	 * so it stays crisp on a high-density screen.
	 */
	let { size = 36 }: { size?: number } = $props();
</script>

<img class="avatar" src="/api/account/avatar?size={size * 2}" width={size} height={size} alt="" />

<style lang="scss">
	.avatar {
		display: block;
		flex: none;
		border-radius: 999px;
		border: 1.5px solid var(--tw-border);
		background: var(--tw-well);
	}
</style>
