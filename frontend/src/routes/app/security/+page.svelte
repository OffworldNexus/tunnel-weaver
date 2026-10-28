<script lang="ts">
	/**
	 * Security overview: what the account signs in with.
	 *
	 * The page's data comes from its loader (`./+page.ts`), which reads the one
	 * endpoint behind this screen, and every action here invalidates that load
	 * instead of refreshing a list it keeps: what the page shows is always the
	 * relay's answer rather than a copy that has to be kept in step by hand.
	 */
	import qrcode from 'qrcode-generator';

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
	import type { AuthenticatorApp, PasskeyView } from '#lib/app/security';
	import { useSession } from '#lib/app/session.svelte';
	import { date, timeAgo } from '#lib/app/time';
	import { climb } from '#lib/app/upgrade';
	import { setMeta } from '#lib/console/meta.svelte';
	import ConfirmDeleteDialog from '#lib/ui/ConfirmDeleteDialog.svelte';
	import Dialog from '#lib/ui/Dialog.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Panel from '#lib/ui/Panel.svelte';
	import { invalidate } from '$app/navigation';
	import { resolve } from '$app/paths';

	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	setMeta({
		title: 'Security',
		subtitle: 'Choose how you sign in. Protect your account.',
		crumbs: [{ label: 'Security' }]
	});

	let busy = $state(false);

	const session = useSession();

	const passkeys = $derived(data.security.passkeys);
	const apps = $derived(data.security.authenticator_apps);

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

	/**
	 * Re-reads the page's data. What every action here ends with: the relay has
	 * just changed something, and the page shows what it says rather than what the
	 * action believed it did.
	 */
	async function reload(): Promise<void> {
		await invalidate('app:security');
	}

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

	/** Whether an enrolment, a confirmation or a removal is in flight. */
	let appBusy = $state(false);
	/** What went wrong with the last authenticator-app action; empty for none. */
	let appError = $state('');
	/** The app a removal is being confirmed for, if any. */
	let removingApp = $state<AuthenticatorApp | null>(null);
	/** The enrolment in progress: the relay's secret, and the URI built from it. */
	let enrol = $state<{ id: number; secret: string; uri: string } | null>(null);
	/** What the person called the app being enrolled; prefilled with a guess. */
	let enrolName = $state('');
	/** The code the person typed for the app being enrolled. */
	let enrolCode = $state('');

	/**
	 * Adding an authenticator app needs `certain`, exactly as adding a passkey
	 * does: it plants a second factor that works without the mailbox. The gate
	 * asks for the proof *first* and the dialog follows it.
	 */
	const enrolModal = certainModal();

	/** What to call one app: what the person named it, or the kind of thing it is. */
	function appLabel(app: AuthenticatorApp): string {
		return app.name !== '' ? app.name : 'Authenticator app';
	}

	/**
	 * What the person types back to remove an app: its name.
	 *
	 * An app they did not name has no name to type, so the account's own address
	 * stands in — what deleting the account asks for — rather than the generic
	 * label that two unnamed apps would share, which would confirm nothing about
	 * which one is going.
	 */
	function appRemovalTarget(app: AuthenticatorApp): string {
		return app.name !== '' ? app.name : expected;
	}

	/** One app's dates, in the console's words. */
	function appMeta(app: AuthenticatorApp): string {
		const added = `Added ${date(app.created_at)}`;
		return app.last_used_at === null
			? `${added} · never used`
			: `${added} · last used ${timeAgo(app.last_used_at)}`;
	}

	/**
	 * The QR an app is set up from, drawn as real SVG nodes.
	 *
	 * Drawn here, in the browser, from the relay's own `otpauth://` URI: the relay
	 * has no business rendering a picture, and the person's device is the only
	 * place the code needs to exist. Built as DOM rather than as markup on
	 * purpose — the only thing the URI changes is *where* the dark modules are, so
	 * there is no string to interpolate and nothing to sanitise. `M` is the
	 * error-correction level with room to spare, since the QR is scanned off a
	 * screen rather than a printed label.
	 */
	function qr(node: HTMLElement, uri: string) {
		const draw = (target: HTMLElement) => {
			const code = qrcode(0, 'M');
			code.addData(uri);
			code.make();
			const modules = code.getModuleCount();
			const ns = 'http://www.w3.org/2000/svg';
			const svg = document.createElementNS(ns, 'svg');
			svg.setAttribute('viewBox', `0 0 ${modules} ${modules}`);
			const path = document.createElementNS(ns, 'path');
			let d = '';
			for (let row = 0; row < modules; row += 1) {
				for (let column = 0; column < modules; column += 1) {
					if (code.isDark(row, column)) {
						d += `M${column} ${row}h1v1h-1z`;
					}
				}
			}
			path.setAttribute('d', d);
			svg.append(path);
			target.append(svg);
		};
		draw(node);
		return {
			update(next: string) {
				node.replaceChildren();
				uri = next;
				draw(node);
			}
		};
	}

	/** The "Add an authenticator app" button: the proof first, then the name. */
	async function addApp(): Promise<void> {
		const suggestion = await suggestedName();
		await enrolModal.begin();
		if (!enrolModal.open) {
			return;
		}
		// A dialog reopened after a step-up still holds a secret the relay can
		// confirm; starting another would leave the first enrolment behind.
		if (enrol) {
			return;
		}
		enrolName = suggestion;
	}

	/**
	 * Starts the enrolment and shows the secret.
	 *
	 * The name is sent *with* the secret rather than after it: it is the label the
	 * authenticator app displays beside the issuer, and the URI the QR carries is
	 * built once — there is no relabelling it afterwards. The `certain` proof can
	 * lapse while the dialog is open (the gate leads the fall by a few seconds),
	 * so a refusal takes the person back up once and finishes what they started,
	 * the same pattern adding a passkey uses.
	 */
	async function beginEnrolment(escalated = false): Promise<void> {
		if (appBusy) {
			return;
		}
		appBusy = true;
		appError = '';
		enrol = null;
		enrolCode = '';
		const res = await api<{ id: number; secret: string; uri: string }>(
			'POST',
			'/api/account/totp/begin',
			{ name: enrolName },
			async (required, options) => {
				if (escalated || !(await climb(required, options))) {
					return;
				}
				await beginEnrolment(true);
			}
		);
		appBusy = false;
		if (!res.ok || !res.data) {
			if (!res.refused) {
				appError = res.error ?? 'We could not start an authenticator app. Try again.';
			}
			return;
		}
		enrol = res.data;
	}

	/** Confirms the enrolment with a code the app itself produced. */
	async function confirmApp(escalated = false): Promise<void> {
		const pending = enrol;
		if (!pending || appBusy) {
			return;
		}
		appBusy = true;
		appError = '';
		const res = await api(
			'POST',
			'/api/account/totp/confirm',
			{ id: pending.id, code: enrolCode },
			async (required, options) => {
				if (escalated || !(await climb(required, options))) {
					return;
				}
				await confirmApp(true);
			}
		);
		appBusy = false;
		if (!res.ok) {
			if (!res.refused) {
				appError = res.error ?? 'That code was not accepted. Try again.';
			}
			return;
		}
		closeEnrolment();
		notify('success', 'Authenticator app added. It signs you in with a code.');
		await reload();
	}

	/** Dismisses the enrolment dialog, forgetting the secret with it. */
	function closeEnrolment(): void {
		enrolModal.close();
		enrol = null;
		enrolName = '';
		enrolCode = '';
		appError = '';
	}

	/** Removes an authenticator app: the confirmation's answer. */
	async function removeApp(): Promise<void> {
		const app = removingApp;
		if (!app || appBusy) {
			return;
		}
		appBusy = true;
		appError = '';
		const res = await api('POST', `/api/account/totp/${app.id}/remove`, {}, () => {
			// Removal only needs `strong`, which this page always holds; a refusal
			// here means the session itself lapsed, and the guard will take over.
		});
		appBusy = false;
		removingApp = null;
		if (!res.ok) {
			if (!res.refused) {
				appError = res.error ?? 'We could not remove that authenticator app.';
			}
			return;
		}
		notify('success', 'Authenticator app removed.');
		await reload();
	}

	/** One of the account's machines, as the relay lists them. */
	interface MachineView {
		name: string;
	}

	/**
	 * What to call a new passkey before the person says otherwise.
	 *
	 * A passkey belongs to a *device*, and the account already knows which devices
	 * it has: the relay lists them most recently used first, so the first named
	 * one is the device this is almost certainly being added on. Failing that (an
	 * account with no machines yet), the browser and the system are a truer name
	 * than either alone — and better than an invented one.
	 */
	async function suggestedName(): Promise<string> {
		const res = await api<{ machines: MachineView[] }>('GET', '/api/account/machines');
		return res.data?.machines.find((machine) => machine.name !== '')?.name ?? browserAndSystem();
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
		await reload();
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
		await reload();
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

	{#if data.security.has_password}
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

	{#if passkeys.length === 0}
		<p class="state">No passkey yet</p>
		<p class="state__note">
			Your password and emailed codes still sign you in. Adding a passkey gives you a way in that
			never leaves your device.
		</p>
	{:else}
		<ul class="credentials">
			{#each passkeys as passkey (passkey.id)}
				<li
					class="credential"
					aria-labelledby={`passkey-label-${passkey.id} passkey-meta-${passkey.id}`}
				>
					<span class="credential__icon">
						<Icon name="fingerprint" size={16} />
						<span class="credential__copy">
							<span class="credential__label" id={`passkey-label-${passkey.id}`}>
								{passkeyLabel(passkey)}
							</span>
							<span class="credential__meta" id={`passkey-meta-${passkey.id}`}>
								{passkeyMeta(passkey)}
							</span>
						</span>
					</span>
					<Keycap
						type="button"
						variant="ghost"
						size="sm"
						disabled={passkeyBusy}
						ariaLabel={`Remove ${passkeyLabel(passkey)}`}
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

<Panel title="Email codes" subtitle="The second factor that goes to your mailbox. It is always on.">
	<p class="state"><Icon name="check" size={16} /> Enabled · always on</p>
	<p class="state__note">
		With no authenticator app set up, signing in sends a one-time code to
		<strong>{session.user?.email || 'your address'}</strong> — so the relay's email provider is required.
		The second factor cannot be turned off.
	</p>
</Panel>

<Panel title="Authenticator apps" subtitle="A second factor that works without your mailbox.">
	{#snippet actions()}
		<Keycap type="button" variant="key" size="sm" disabled={appBusy} onclick={addApp}>
			<Icon name="shield" size={14} /> Add an authenticator app
		</Keycap>
	{/snippet}

	{#if apps.length === 0}
		<p class="state">No authenticator app yet</p>
		<p class="state__note">
			Adding one gives you a second factor that works without your mailbox. An account can hold as
			many as you like, and sign-in offers the app before the emailed code.
		</p>
	{:else}
		<ul class="credentials">
			{#each apps as app (app.id)}
				<li class="credential" aria-labelledby={`app-label-${app.id} app-meta-${app.id}`}>
					<span class="credential__icon">
						<Icon name="shield" size={16} />
						<span class="credential__copy">
							<span class="credential__label" id={`app-label-${app.id}`}>{appLabel(app)}</span>
							<span class="credential__meta" id={`app-meta-${app.id}`}>{appMeta(app)}</span>
						</span>
					</span>
					<Keycap
						type="button"
						variant="ghost"
						size="sm"
						disabled={appBusy}
						ariaLabel={`Remove ${appLabel(app)}`}
						onclick={() => (removingApp = app)}
					>
						<Icon name="trash" size={14} /> Remove
					</Keycap>
				</li>
			{/each}
		</ul>
	{/if}

	{#if appError}
		<p class="notice-error" role="alert">{appError}</p>
	{/if}
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

<!--
	Removing an authenticator app is confirmed by naming it, like everything else
	the console removes. It is not a `certain` action: the account keeps its other
	factors and the emailed code still signs it in.
-->
<ConfirmDeleteDialog
	open={removingApp !== null}
	title="Remove this authenticator app?"
	expected={removingApp === null ? '' : appRemovalTarget(removingApp)}
	caseInsensitive={removingApp !== null && removingApp.name === ''}
	confirmLabel="Remove app"
	cancelLabel="Keep it"
	onConfirm={removeApp}
	onClose={() => (removingApp = null)}
>
	<p>
		Codes from this app will no longer sign you in, and nothing else about the account changes. Your
		password and emailed codes still work.
	</p>
	{#if removingApp !== null && removingApp.name === ''}
		<p>
			This app was never given a name, so type your account address to confirm it is the one you
			mean.
		</p>
	{/if}
</ConfirmDeleteDialog>

<!--
	The enrolment, in the order the relay needs it: the name first, because it is
	the label the authenticator app displays and the URI the QR carries is built
	once — then the QR with the key behind it, then the code the app produces,
	which is what makes the app a factor rather than a picture. The dialog is taken
	away whenever the proof behind it lapses, and the secret goes with it.
-->
<Dialog
	bind:open={enrolModal.open}
	title="Add an authenticator app"
	width={520}
	onClose={closeEnrolment}
>
	{#snippet footer()}
		<Keycap type="button" variant="key" onclick={closeEnrolment} disabled={appBusy}>Cancel</Keycap>
		{#if enrol === null}
			<Keycap type="button" variant="primary" loading={appBusy} onclick={() => beginEnrolment()}>
				Continue
			</Keycap>
		{:else}
			<Keycap type="button" variant="primary" loading={appBusy} onclick={() => confirmApp()}>
				Confirm
			</Keycap>
		{/if}
	{/snippet}

	{#if enrol === null}
		<!--
			A plain form, so Enter in the field is the same submit as the keycap: the
			person names the app once, either way.
		-->
		<form
			class="stack"
			onsubmit={(event) => {
				event.preventDefault();
				void beginEnrolment();
			}}
		>
			<div class="field">
				<label for="app-name">Name</label>
				<input
					id="app-name"
					class="control"
					type="text"
					bind:value={enrolName}
					disabled={appBusy}
					autocomplete="off"
					aria-describedby="app-name-hint"
				/>
			</div>
			<p class="state__note" id="app-name-hint">
				A device name is a good one: it is what this app is called here and in your authenticator,
				so several enrolled apps are told apart.
			</p>
		</form>
	{:else}
		<div class="enrol">
			<!--
				The QR is a picture of the key beside it. The key in text is the
				accessible way to set the app up, so the graphic is hidden from
				assistive technology rather than announced as an image of nothing.
			-->
			<div class="enrol__qr" aria-hidden="true" use:qr={enrol.uri}></div>
			<div class="enrol__copy">
				<p class="state__note">
					Scan this with your authenticator app — or type the key in by hand.
				</p>
				<p class="enrol__key">
					<span class="enrol__key-label" id="app-secret-label">Setup key</span>
					<code class="enrol__secret" aria-labelledby="app-secret-label">{enrol.secret}</code>
				</p>
			</div>
		</div>

		<!--
			A plain form, so Enter in the field is the same submit as the keycap:
			the person confirms the app once, either way.
		-->
		<form
			class="stack"
			onsubmit={(event) => {
				event.preventDefault();
				void confirmApp();
			}}
		>
			<div class="field">
				<label for="app-code">Code from the app</label>
				<input
					id="app-code"
					class="control"
					inputmode="numeric"
					autocomplete="one-time-code"
					autocapitalize="off"
					spellcheck="false"
					maxlength="6"
					placeholder="000000"
					bind:value={enrolCode}
					disabled={appBusy}
				/>
			</div>
		</form>
	{/if}

	<!--
		Rendered even while empty, on purpose: the space a refusal takes is reserved
		in advance, so the dialog cannot grow the moment one arrives — and a live
		region that is already in the page is the one a screen reader reliably
		announces.
	-->
	<p class="notice-error dialog-error" role="alert">{appError}</p>
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

	/* One row per credential: a passkey, or an authenticator app (WVR-166). Both
	   list the same way — an icon, a label with its dates, and what can be done
	   with it. */
	.credentials {
		list-style: none;
		margin: 12px 0 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.credential {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
	}

	.credential__icon {
		display: flex;
		align-items: center;
		gap: 10px;
		min-width: 0;
	}

	.credential__icon :global(svg) {
		flex: none;
		color: var(--tw-muted);
	}

	.credential__copy {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
	}

	.credential__label {
		font-weight: 700;
	}

	.credential__meta {
		color: var(--tw-muted);
		font-size: 14px;
	}

	/* The console's error line carries no margin of its own, and the dialog body
	   stacks its children flush. One line of the error's own type is reserved
	   whatever is in it, so a refusal arriving cannot resize the dialog: the
	   reservation is the message's height, not a margin added with it. */
	.dialog-error {
		margin-top: 8px;
		line-height: 1.5;
		min-height: 1.5em;
	}

	/* The enrolment dialog: the QR beside the key it encodes, so either way of
	   setting the app up is one glance away. */
	.enrol {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-start;
		gap: 20px;
		margin-bottom: 16px;
	}

	.enrol__qr {
		flex: none;
		width: 140px;
		padding: 8px;
		background: #fff;
		border-radius: 4px;
	}

	.enrol__qr :global(svg) {
		display: block;
		width: 100%;
		height: auto;
	}

	.enrol__copy {
		display: flex;
		flex-direction: column;
		gap: 8px;
		/* A basis it can be measured at: without one, the copy's max-content size
		   is the note's own max-width, which is wider than the space beside the
		   QR — so the whole column wrapped under it. */
		flex: 1 1 220px;
		min-width: 0;
	}

	/* The side column's note wraps at its column, not at the page's reading
	   width, so the key really does sit beside the code that encodes it. */
	.enrol__copy .state__note {
		max-width: 34ch;
	}

	.enrol__key {
		display: flex;
		flex-direction: column;
		gap: 2px;
		margin: 0;
	}

	.enrol__key-label {
		color: var(--tw-muted);
		font-size: 13px;
	}

	.enrol__secret {
		font-family: var(--tw-mono);
		font-size: 13px;
		letter-spacing: 1px;
		word-break: break-all;
		user-select: all;
	}
</style>
