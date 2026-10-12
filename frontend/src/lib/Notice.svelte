<script lang="ts">
	import { notices, dismiss } from '#lib/notices';
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
