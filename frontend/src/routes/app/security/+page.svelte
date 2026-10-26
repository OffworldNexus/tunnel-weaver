<script lang="ts">
	/** Security overview: what the account signs in with. */
	import { api } from '#lib/account/api';
	import { notify } from '#lib/account/notices';
	import { flow } from '#lib/account/state';
	import {
		createCredential,
		failureOf,
		type PasskeyOptions,
		supported as passkeysSupported
	} from '#lib/account/webauthn';
	import { certainModal } from '#lib/app/certainModal.svelte';
	import { useSession } from '#lib/app/session.svelte';
	import { date, timeAgo } from '#lib/app/time';
	import { climb } from '#lib/app/upgrade';
	import { setMeta } from '#lib/console/meta.svelte';
	import ConfirmDeleteDialog from '#lib/ui/ConfirmDeleteDialog.svelte';
	import Dialog from '#lib/ui/Dialog.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Panel from '#lib/ui/Panel.svelte';
	import { resolve } from '$app/paths';

	setMeta({
		title: 'Security',
		subtitle: 'Choose how you sign in. Protect your account.',
		crumbs: [{ label: 'Security' }]
	});

	let busy = $state(false);

	const session = useSession();

	/**
	 * What the user must type back: the address when there is one, else the
	 * display name — the same pair the relay re-checks server-side.
	 */
	const expected = $derived(session.user?.email || session.user?.name || '');

	/**
	 * Deleting needs `certain` — the password, or a passkey, proven moments ago.
	 * The gate asks for it *first* and shows the confirmation only after, and it
	 * takes the confirmation away again if the proof lapses while it is open.
	 */
	const deleteModal = certainModal();

	/** One of the account's passkeys, as the relay lists it (WVR-163). */
	interface PasskeyView {
		id: number;
		/** What the person called it; empty when they did not name it. */
		name: string;
		transports: string[];
		created_at: number;
		last_used_at: number | null;
	}

	/** The account's passkeys, or null while they are still being read. */
	let passkeys = $state<PasskeyView[] | null>(null);
	/** Whether a passkey ceremony or a removal is in flight. */
	let passkeyBusy = $state(false);
	/** What went wrong with the last passkey action; empty for none. */
	let passkeyError = $state('');
	/** The passkey a removal is being confirmed for, if any. */
	let removing = $state<PasskeyView | null>(null);
	/** The name, as typed in the "add one" dialog; prefilled with its default. */
	let newName = $state('');

	/**
	 * Adding a passkey needs `certain` — a credential outlives every password, so
	 * planting one takes a proof of presence — and the gate asks for it *first*,
	 * exactly as deleting does. The naming dialog is what follows.
	 */
	const namingModal = certainModal();

	/** Whether this browser can run a passkey ceremony at all. */
	const passkeysSupportedHere = passkeysSupported();

	/** One of the account's machines, as the relay lists them. */
	interface MachineView {
		name: string;
		/** When it was last seen; `null` when it never was. */
		last_seen_at: number | null;
	}

	/**
	 * What to call a new passkey before the person says otherwise.
	 *
	 * A passkey belongs to a *device*, and the account already knows which devices
	 * it has: the one that was most recently alive is the one this is almost
	 * certainly being added on, so its name is the default. Failing that (an
	 * account with no machines yet), the browser and the system are a truer name
	 * than either alone — and better than an invented one.
	 */
	async function suggestedName(): Promise<string> {
		const res = await api<{ machines: MachineView[] }>('GET', '/api/account/machines?per_page=200');
		const newest = (res.data?.machines ?? [])
			.filter((machine) => machine.name !== '')
			.sort((left, right) => (right.last_seen_at ?? 0) - (left.last_seen_at ?? 0))[0];
		return newest?.name ?? browserAndSystem();
	}

	/** "Chrome on Linux": what this browser is, as plainly as the UA allows. */
	function browserAndSystem(): string {
		const agent = navigator.userAgent;
		const browsers: [RegExp, string][] = [
			[/Firefox\//, 'Firefox'],
			[/Edg\//, 'Edge'],
			[/OPR\//, 'Opera'],
			[/Chrome\//, 'Chrome'],
			[/Safari\//, 'Safari']
		];
		const systems: [RegExp, string][] = [
			[/Android/i, 'Android'],
			[/iPhone|iPad|iPod/i, 'iOS'],
			[/Mac/i, 'macOS'],
			[/Win/i, 'Windows'],
			[/Linux/i, 'Linux']
		];
		const uaData = navigator as Navigator & { userAgentData?: { platform?: string } };
		const platform = uaData.userAgentData?.platform ?? navigator.platform ?? '';
		const browser = browsers.find(([pattern]) => pattern.test(agent))?.[1] ?? 'Browser';
		const system = systems.find(([pattern]) => pattern.test(platform))?.[1] ?? 'your system';
		return `${browser} on ${system}`;
	}

	/** The "Add a passkey" button: ask for the proof, then name the credential. */
	async function addPasskey() {
		const suggestion = await suggestedName();
		await namingModal.begin();
		if (namingModal.open) {
			newName = suggestion;
		}
	}

	/** What to call a passkey the person did not name. */
	function passkeyLabel(passkey: PasskeyView): string {
		if (passkey.name !== '') {
			return passkey.name;
		}
		// The transport is the one hint the authenticator gave about itself: a
		// platform one ("internal") is this very device, anything else is a key
		// the person carries.
		return passkey.transports.includes('internal') ? 'This device' : 'Security key';
	}

	/** One passkey's dates, in the console's words. */
	function passkeyMeta(passkey: PasskeyView): string {
		const added = `Added ${date(passkey.created_at)}`;
		return passkey.last_used_at === null
			? `${added} · never used`
			: `${added} · last used ${timeAgo(passkey.last_used_at)}`;
	}

	async function loadPasskeys() {
		const res = await api<{ passkeys: PasskeyView[] }>('GET', '/api/account/passkeys');
		if (res.ok && res.data) {
			passkeys = res.data.passkeys;
		} else {
			passkeys = [];
			passkeyError = res.error ?? 'We could not read your passkeys.';
		}
	}

	$effect(() => {
		void loadPasskeys();
	});

	/**
	 * Registers a passkey: the ceremony, from the naming dialog's answer.
	 *
	 * The proof is already in hand — the gate asked for it before the dialog was
	 * shown — so this only has to run the ceremony. A refusal can still arrive if
	 * the proof lapses in the gap (the gate leads the fall by a few seconds); the
	 * handler takes the person back up once and finishes what they started.
	 */
	async function registerPasskey(escalated = false) {
		if (passkeyBusy) {
			return;
		}
		passkeyError = '';
		passkeyBusy = true;
		const begun = await api<PasskeyOptions>(
			'POST',
			'/api/account/passkeys/begin',
			{},
			async (required, options) => {
				// Proof aged out between the gate and this call. Prove it again and
				// finish what the person started — once, so a refusal that is *not*
				// about the level cannot loop.
				if (escalated || !(await climb(required, options))) {
					return;
				}
				await registerPasskey(true);
			}
		);
		if (!begun.ok || !begun.data) {
			passkeyBusy = false;
			if (!begun.refused) {
				passkeyError = begun.error ?? 'We could not start that passkey. Try again.';
			}
			return;
		}
		let credential: unknown;
		try {
			credential = await createCredential(begun.data.options);
		} catch (error) {
			passkeyBusy = false;
			if (failureOf(error) === 'cancelled') {
				return;
			}
			passkeyError = passkeysSupportedHere
				? 'That passkey was not accepted. Try again.'
				: 'This browser cannot use passkeys.';
			return;
		}
		const done = await api(
			'POST',
			'/api/account/passkeys/finish',
			{ handle: begun.data.handle, label: newName, credential },
			async (required, options) => {
				if (escalated || !(await climb(required, options))) {
					return;
				}
				await registerPasskey(true);
			}
		);
		passkeyBusy = false;
		if (!done.ok) {
			if (!done.refused) {
				passkeyError = done.error ?? 'That passkey was not accepted. Try again.';
			}
			return;
		}
		namingModal.close();
		newName = '';
		notify('success', 'Passkey added. It can sign you in on its own.');
		await loadPasskeys();
	}

	/** Removes a passkey: the confirmation's answer. */
	async function removePasskey() {
		const passkey = removing;
		if (!passkey || passkeyBusy) {
			return;
		}
		passkeyBusy = true;
		passkeyError = '';
		const res = await api('POST', `/api/account/passkeys/${passkey.id}/remove`, {}, () => {
			// Removal only needs `strong`, which this page always holds; a refusal
			// here means the session itself lapsed, and the guard will take over.
		});
		passkeyBusy = false;
		removing = null;
		if (!res.ok) {
			if (!res.refused) {
				passkeyError = res.error ?? 'We could not remove that passkey.';
			}
			return;
		}
		notify('success', 'Passkey removed.');
		await loadPasskeys();
	}

	async function deleteAccount(address: string, escalated = false) {
		busy = true;
		// Success ends every session; do not let the guard see it before we leave.
		session.detach();
		const res = await api('POST', '/api/account/delete', { address }, async (required, options) => {
			// The proof aged out between the gate and this submit — the race the
			// gate's own lead almost always wins first. Prove it again and finish
			// what the person confirmed. Once only: a refusal that is *not* about
			// the level must not loop.
			if (escalated || !(await climb(required, options))) {
				return;
			}
			await deleteAccount(address, true);
		});
		busy = false;
		deleteModal.close();
		if (!res.ok) {
			session.restart();
			if (res.refused) {
				// A second refusal is not about the level: rather than swallow the
				// click, ask for the proof again and leave the confirmation be.
				if (escalated) {
					void deleteModal.begin();
				}
				return;
			}
			notify('error', res.error ?? 'We could not delete your account. Please try again.');
			return;
		}
		// The relay removed every session and cleared both cookies. A full load
		// (not a `goto`) keeps the console from watching the session lapse and
		// reporting a spurious "session expired"; sign-in shows the notice.
		flow.save({ notice: 'Your account and all its data have been deleted.' });
		window.location.assign(resolve('/(auth)/sign-in'));
	}
</script>

<Panel
	title="Password"
	subtitle="Your password signs you in and authorises changes to the account."
>
	{#snippet actions()}
		<Keycap href={resolve('/app/security/password')} variant="key" size="sm">
			<Icon name="lock" size={14} /> Change password
		</Keycap>
	{/snippet}

	{#if session.user?.has_password}
		<p class="state"><Icon name="check" size={16} /> Password is set</p>
	{:else}
		<p class="state">No password is set</p>
	{/if}
</Panel>

<Panel
	title="Passkeys"
	subtitle="Sign in with your face, fingerprint, PIN or a security key. No password, no emailed code."
>
	{#snippet actions()}
		<Keycap
			type="button"
			variant="key"
			size="sm"
			disabled={passkeyBusy || !passkeysSupportedHere}
			onclick={addPasskey}
		>
			<Icon name="fingerprint" size={14} /> Add a passkey
		</Keycap>
	{/snippet}

	{#if passkeys === null}
		<p class="state">Reading your passkeys…</p>
	{:else if passkeys.length === 0}
		<p class="state">No passkey yet</p>
		<p class="state__note">
			Your password and emailed codes still sign you in. Adding a passkey gives you a way in that
			never leaves your device.
		</p>
	{:else}
		<ul class="passkeys">
			{#each passkeys as passkey (passkey.id)}
				<li class="passkey">
					<span class="passkey__device">
						<Icon name="fingerprint" size={16} />
						<span class="passkey__copy">
							<span class="passkey__label">{passkeyLabel(passkey)}</span>
							<span class="passkey__meta">{passkeyMeta(passkey)}</span>
						</span>
					</span>
					<Keycap
						type="button"
						variant="ghost"
						size="sm"
						disabled={passkeyBusy}
						onclick={() => (removing = passkey)}
					>
						<Icon name="trash" size={14} /> Remove
					</Keycap>
				</li>
			{/each}
		</ul>
	{/if}

	{#if !passkeysSupportedHere}
		<p class="state__note">
			This browser cannot use passkeys. Everything else here works as usual.
		</p>
	{/if}
	{#if passkeyError}
		<p class="notice-error" role="alert">{passkeyError}</p>
	{/if}
</Panel>

<Panel
	title="Two-factor authentication"
	subtitle="A second factor protects your account even if your password leaks. It is always on."
>
	<p class="state"><Icon name="check" size={16} /> Enabled · email codes</p>
	<p class="state__note">
		Every sign-in sends a one-time code to
		<strong>{session.user?.email || 'your address'}</strong>. The relay's email provider is
		therefore required, and there is no way to turn the second factor off.
	</p>
</Panel>

<Panel danger title="Danger zone" subtitle="Irreversible actions. There is no way back.">
	<div class="danger">
		<div class="danger__copy">
			<p class="danger__title">Delete your account</p>
			<p class="danger__note">
				Removes your account, unpairs every machine and tunnel, and deletes all of your usage
				history. This cannot be undone.
			</p>
		</div>
		<Keycap type="button" variant="danger" disabled={busy} onclick={() => void deleteModal.begin()}>
			<Icon name="trash" size={14} /> Delete account
		</Keycap>
	</div>
</Panel>

<ConfirmDeleteDialog
	bind:open={deleteModal.open}
	caseInsensitive
	title="Delete your account?"
	{expected}
	confirmLabel="Delete account"
	cancelLabel="Keep my account"
	onConfirm={deleteAccount}
>
	<p>
		This permanently deletes your account, every paired machine and tunnel, and all of your usage
		history. Nothing is retained and nothing can be recovered.
	</p>
</ConfirmDeleteDialog>

<!--
	Removing a passkey is confirmed the same way the console confirms anything
	destructive: by naming it. It is the account's own list, so the name is right
	there to type back.
-->
<ConfirmDeleteDialog
	open={removing !== null}
	title="Remove this passkey?"
	expected={removing ? passkeyLabel(removing) : ''}
	confirmLabel="Remove passkey"
	cancelLabel="Keep it"
	onConfirm={removePasskey}
	onClose={() => (removing = null)}
>
	<p>
		This passkey will no longer sign you in, and nothing else about the account changes. Your
		password and emailed codes still work.
	</p>
</ConfirmDeleteDialog>

<Dialog
	bind:open={namingModal.open}
	title="Add a passkey"
	width={460}
	onClose={() => namingModal.close()}
>
	{#snippet footer()}
		<Keycap type="button" variant="key" onclick={() => namingModal.close()} disabled={passkeyBusy}>
			Cancel
		</Keycap>
		<Keycap type="button" variant="primary" loading={passkeyBusy} onclick={() => registerPasskey()}>
			<Icon name="fingerprint" size={14} /> Create passkey
		</Keycap>
	{/snippet}

	<!--
		A plain form, so Enter in the field is the same submit as the keycap: the
		person names the passkey once, either way.
	-->
	<form
		class="stack"
		onsubmit={(event) => {
			event.preventDefault();
			void registerPasskey();
		}}
	>
		<div class="field">
			<label for="passkey-name">Name</label>
			<input
				id="passkey-name"
				class="control"
				type="text"
				bind:value={newName}
				disabled={passkeyBusy}
				autocomplete="off"
			/>
		</div>
	</form>

	<p class="hint">
		Your browser will ask for your face, fingerprint, PIN or security key, and then the passkey
		lives on that authenticator — it never reaches the relay.
	</p>
</Dialog>

<style lang="scss">
	.state {
		display: flex;
		align-items: center;
		gap: 8px;
		margin: 0;
		color: var(--tw-muted);
	}

	.state :global(svg) {
		color: var(--tw-online);
	}

	.state__note {
		margin: 8px 0 0;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.5;
		max-width: 60ch;
	}

	.danger {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
	}

	.danger__copy {
		min-width: 0;
	}

	.danger__title {
		font-weight: 700;
		margin-bottom: 2px;
	}

	.danger__note {
		margin: 0;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.5;
		max-width: 60ch;
	}

	.passkeys {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.passkey {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
	}

	.passkey__device {
		display: flex;
		align-items: center;
		gap: 10px;
		min-width: 0;
	}

	.passkey__device :global(svg) {
		flex: none;
		color: var(--tw-muted);
	}

	.passkey__copy {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
	}

	.passkey__label {
		font-weight: 700;
	}

	.passkey__meta {
		color: var(--tw-muted);
		font-size: 14px;
	}
</style>
