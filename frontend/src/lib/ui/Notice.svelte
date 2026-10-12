<script lang="ts">
	import { notices, dismiss } from '#lib/account/notices';
</script>

<!-- Global notice/error surface. `aria-live` announces network failures and
     session-expiry messages without stealing focus. -->
<div class="notices" aria-live="polite" aria-relevant="additions">
	{#each $notices as notice (notice.id)}
		<div class="notice notice--{notice.kind}">
			<span class="notice__text">{notice.message}</span>
			<button
				type="button"
				class="notice__close"
				aria-label="Dismiss message"
				on:click={() => dismiss(notice.id)}
			>
				×
			</button>
		</div>
	{/each}
</div>

<style lang="scss">
	.notices {
		position: fixed;
		inset: 14px 14px auto 14px;
		z-index: 20;
		display: flex;
		flex-direction: column;
		gap: 10px;
		margin: 0 auto;
		width: min(100%, 416px);
		pointer-events: none;
	}

	.notice {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		padding: 12px 14px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
		pointer-events: auto;
		font-size: 14px;
	}

	.notice--error {
		border-color: var(--tw-danger);
		color: var(--tw-danger);
	}

	.notice--success {
		border-color: var(--tw-success);
		color: var(--tw-success);
	}

	.notice__text {
		flex: 1;
	}

	.notice__close {
		border: 0;
		background: none;
		color: inherit;
		font-size: 1.15rem;
		line-height: 1;
		cursor: pointer;
		opacity: 0.7;
	}

	.notice__close:hover {
		opacity: 1;
	}
</style>
