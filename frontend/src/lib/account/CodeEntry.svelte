<script lang="ts">
	/**
	 * The six-digit code step, shared by the signup verification and the
	 * sign-in second factor: where the code comes from, the field, and the
	 * page's secondary actions.
	 *
	 * The page injects what differs — the source it names, and `submit`, which
	 * sends the code and resolves to an error message or to nothing once it has
	 * moved on.
	 */
	import type { Snippet } from 'svelte';

	import { jsonForm } from '#lib/account/form';
	import { verifyCodeSchema } from '#lib/account/schemas';
	import Icon from '#lib/ui/Icon.svelte';
	import type { IconName } from '#lib/ui/icons';
	import Keycap from '#lib/ui/Keycap.svelte';

	interface Props {
		/** The source's icon. */
		icon: IconName;
		/** The source's name, shown as a chip. */
		source: string;
		/** The sentence under the chip, which the field is described by. */
		detail: Snippet;
		/** Sends the code. */
		submit: (code: string) => Promise<string | null | void>;
		/** The row of secondary actions under the form. */
		actions?: Snippet;
		/** A status line about those actions; empty for none. */
		status?: string;
	}

	let { icon, source, detail, submit, actions, status = '' }: Props = $props();

	const { form, errors, message, submitting, enhance } = jsonForm(
		verifyCodeSchema,
		{ code: '' },
		({ code }) => submit(code)
	);
</script>

<!--
	Where the code is coming from, before anything asks for it. The name is a
	chip so it reads as a label rather than as more prose, and the detail is what
	the field is described by.
-->
<div class="source">
	<span class="source__icon" aria-hidden="true">
		<Icon name={icon} size={20} />
	</span>
	<div class="source__copy">
		<span class="source__name">{source}</span>
		<p class="source__detail" id="code-source">{@render detail()}</p>
	</div>
</div>

<form class="form" method="POST" use:enhance novalidate>
	<div class="field">
		<label for="code">Code</label>
		<input
			id="code"
			name="code"
			class="code"
			inputmode="numeric"
			autocomplete="one-time-code"
			autocapitalize="off"
			spellcheck="false"
			maxlength="6"
			placeholder="000000"
			bind:value={$form.code}
			disabled={$submitting}
			aria-invalid={$errors.code ? 'true' : undefined}
			aria-describedby={$errors.code ? 'code-source code-error' : 'code-source'}
		/>
		{#if $errors.code}<p id="code-error" class="field__error" aria-live="polite">
				{$errors.code[0]}
			</p>{/if}
	</div>

	{#if $message}
		<p class="notice-error" role="alert">{$message}</p>
	{/if}

	<Keycap type="submit" loading={$submitting} wide>
		{$submitting ? 'Checking…' : 'Continue'}
	</Keycap>
</form>

{#if actions}
	<div class="secondary">{@render actions()}</div>
{/if}
{#if status}<p class="hint status" role="status">{status}</p>{/if}

<style lang="scss">
	.source {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		margin-top: 16px;
		padding: 14px 16px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-deck);
	}

	.source__icon {
		flex: none;
		display: flex;
		margin-top: 2px;
		color: var(--tw-muted);
	}

	.source__copy {
		display: flex;
		flex-direction: column;
		gap: 6px;
		min-width: 0;
	}

	.source__name {
		align-self: flex-start;
		padding: 1px 9px;
		border: 1.5px solid currentColor;
		border-radius: 999px;
		font-size: 11px;
		font-weight: 700;
		letter-spacing: 1.2px;
		text-transform: uppercase;
	}

	.source__detail {
		margin: 0;
		color: var(--tw-muted);
		font-size: 15px;
		line-height: 1.5;
	}

	.code {
		font-family: var(--tw-mono);
		font-size: 24px;
		letter-spacing: 8px;
		text-align: center;
	}

	/* Secondary actions on one line, sized to their labels, so none reads as a
	   competing primary next to `Continue`. */
	.secondary {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 12px;
		margin-top: 24px;
	}

	/* Kept close to the row it reports on, rather than reading as a page caption. */
	.status {
		margin-top: 8px;
	}
</style>
