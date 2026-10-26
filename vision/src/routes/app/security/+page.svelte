<script lang="ts">
	import Badge from '#lib/console/Badge.svelte';
	import Dialog from '#lib/console/Dialog.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import Toggle from '#lib/console/Toggle.svelte';
	import { setMeta } from '#lib/console/meta';
	import { notify } from '#lib/account/notices';
	import { date, timeAgo } from '#lib/mock/format';
	import { machines } from '#lib/mock/store';
	import { current } from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';

	setMeta({
		title: 'Security',
		subtitle: 'How you sign in, and where you are signed in.',
		crumbs: [{ label: 'Security' }]
	});

	let twoFactor = true;
	let changingPassword = false;
	let namingPasskey = false;
	let passkeyName = '';
	// WVR-163: passkeys are a way in of their own — one gesture, no password and
	// no emailed code — and each one is named, or labelled from the transport the
	// authenticator reported.
	let passkeys = [
		{
			id: 'p1',
			name: 'MacBook Pro',
			kind: 'This device',
			at: new Date(Date.now() - 92 * 86_400_000).toISOString(),
			used: new Date(Date.now() - 2 * 3600_000).toISOString()
		},
		{
			id: 'p2',
			name: '',
			kind: 'Security key',
			at: new Date(Date.now() - 14 * 86_400_000).toISOString(),
			used: null
		}
	];
	let sessions = [
		{
			id: 's1',
			device: 'Chrome · Linux',
			ip: '203.0.113.7',
			region: 'fra1',
			current: true,
			at: new Date().toISOString()
		},
		{
			id: 's2',
			device: 'Safari · macOS',
			ip: '198.51.100.24',
			region: 'cdg1',
			current: false,
			at: new Date(Date.now() - 3 * 3600_000).toISOString()
		},
		{
			id: 's3',
			device: 'weave CLI',
			ip: '192.0.2.51',
			region: 'ams3',
			current: false,
			at: new Date(Date.now() - 26 * 3600_000).toISOString()
		}
	];

	function revoke(id: string) {
		sessions = sessions.filter((s) => s.id !== id);
		notify('success', 'Session revoked.');
	}

	function removePasskey(id: string) {
		passkeys = passkeys.filter((p) => p.id !== id);
		notify('success', 'Passkey removed.');
	}

	/**
	 * The name comes prefilled with the account's most recently seen machine —
	 * the device this is almost certainly being added on — and falls back to the
	 * browser and the system. The real console derives the same thing; this is
	 * the design.
	 */
	function beginPasskey() {
		passkeyName = $machines[0]?.name ?? 'Chrome on Linux';
		namingPasskey = true;
	}
</script>

<div class="grid grid--wide">
	<Panel title="Password" subtitle="The credential you sign in with">
		<p class="state">
			<span class="check" aria-hidden="true">✓</span> Password is set
		</p>
		<Keycap type="button" variant="key" onclick={() => (changingPassword = true)}>
			<Icon name="lock" size={15} /> Change password
		</Keycap>
	</Panel>

	<Panel title="Two-factor authentication" subtitle="A second factor on every sign-in">
		<Toggle bind:checked={twoFactor} label={twoFactor ? 'Enabled · TOTP' : 'Disabled'} />
		<p class="muted hint-row">
			{twoFactor
				? 'Recovery codes generated on 2026-08-02 · 8 remaining.'
				: 'Strongly recommended for accounts with paired machines.'}
		</p>
	</Panel>
</div>

<Panel flush title="Passkeys" subtitle="{passkeys.length} registered">
	<svelte:fragment slot="actions">
		<Keycap type="button" size="sm" variant="key" onclick={beginPasskey}>
			<Icon name="fingerprint" size={14} /> Add a passkey
		</Keycap>
	</svelte:fragment>
	<table class="table">
		<thead>
			<tr><th>Passkey</th><th>Kind</th><th>Added</th><th>Last used</th><th></th></tr>
		</thead>
		<tbody>
			{#each passkeys as p (p.id)}
				<tr>
					<td>
						<span class="device"><Icon name="fingerprint" size={15} /> {p.name || 'Unnamed'}</span>
					</td>
					<td class="muted">{p.kind}</td>
					<td class="muted">{date(p.at)}</td>
					<td class="muted">{p.used ? timeAgo(p.used) : 'never'}</td>
					<td class="right">
						<Keycap type="button" size="sm" variant="ghost" onclick={() => removePasskey(p.id)}>
							Remove
						</Keycap>
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
	<p class="muted hint-row">
		A passkey signs you in on its own — no password, no emailed code. It lives on your device or
		security key, and your password stays the way back in if you lose it.
	</p>
</Panel>

<Panel flush title="Active sessions" subtitle="{sessions.length} signed in">
	<table class="table">
		<thead>
			<tr><th>Device</th><th>IP</th><th>Region</th><th>Signed in</th><th></th></tr>
		</thead>
		<tbody>
			{#each sessions as s (s.id)}
				<tr>
					<td>
						<span class="device">
							<Icon name={s.device.includes('CLI') ? 'terminal' : 'globe'} size={15} />
							{s.device}
							{#if s.current}<Badge variant="ok">this session</Badge>{/if}
						</span>
					</td>
					<td class="mono muted">{s.ip}</td>
					<td class="mono muted">{s.region}</td>
					<td class="muted">{timeAgo(s.at)}</td>
					<td class="right">
						{#if !s.current}
							<Keycap type="button" size="sm" variant="ghost" onclick={() => revoke(s.id)}>
								Revoke
							</Keycap>
						{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</Panel>

<Dialog bind:open={changingPassword} title="Change password" width={440}>
	<div class="stack form">
		<div class="stack">
			<label for="current-password">Current password</label>
			<input id="current-password" class="control" type="password" placeholder="••••••••" />
		</div>
		<div class="stack">
			<label for="new-password">New password</label>
			<input
				id="new-password"
				class="control"
				type="password"
				placeholder="At least 12 characters"
			/>
		</div>
	</div>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (changingPassword = false)}>Cancel</Keycap>
		<Keycap
			type="button"
			variant="primary"
			onclick={() => {
				changingPassword = false;
				notify('success', 'Password updated.');
			}}
		>
			Update password
		</Keycap>
	</svelte:fragment>
</Dialog>

<Dialog bind:open={namingPasskey} title="Add a passkey" width={440}>
	<div class="stack form">
		<p class="muted">
			Your browser will ask for your face, fingerprint, PIN or security key. The passkey then lives
			on that authenticator — it never reaches the relay.
		</p>
		<div class="stack">
			<label for="passkey-name">Name</label>
			<input id="passkey-name" class="control" type="text" bind:value={passkeyName} />
		</div>
	</div>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (namingPasskey = false)}>Cancel</Keycap>
		<Keycap
			type="button"
			variant="primary"
			onclick={() => {
				passkeys = [
					...passkeys,
					{
						id: `p${passkeys.length + 1}`,
						name: passkeyName,
						kind: 'This device',
						at: new Date().toISOString(),
						used: null
					}
				];
				passkeyName = '';
				namingPasskey = false;
				notify('success', 'Passkey added.');
			}}
		>
			<Icon name="fingerprint" size={14} /> Create passkey
		</Keycap>
	</svelte:fragment>
</Dialog>

<style lang="scss">
	.state {
		display: flex;
		align-items: center;
		gap: 8px;
		margin: 4px 0 16px;
		font-weight: 700;
	}

	.check {
		color: var(--tw-success);
	}

	.hint-row {
		margin-top: 12px;
		font-size: 13px;
	}

	.device {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		font-weight: 700;
	}

	.form {
		margin-top: 0;
	}
</style>
