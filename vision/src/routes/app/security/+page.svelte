<script lang="ts">
	import Badge from '#lib/console/Badge.svelte';
	import Dialog from '#lib/console/Dialog.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import Toggle from '#lib/console/Toggle.svelte';
	import { setMeta } from '#lib/console/meta';
	import { notify } from '#lib/account/notices';
	import { timeAgo } from '#lib/mock/format';
	import { current } from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';

	setMeta({ title: 'Security', subtitle: 'How you sign in, and where you are signed in.', crumbs: [{ label: 'Security' }] });

	let twoFactor = true;
	let changingPassword = false;
	let sessions = [
		{ id: 's1', device: 'Chrome · Linux', ip: '203.0.113.7', region: 'fra1', current: true, at: new Date().toISOString() },
		{ id: 's2', device: 'Safari · macOS', ip: '198.51.100.24', region: 'cdg1', current: false, at: new Date(Date.now() - 3 * 3600_000).toISOString() },
		{ id: 's3', device: 'weave CLI', ip: '192.0.2.51', region: 'ams3', current: false, at: new Date(Date.now() - 26 * 3600_000).toISOString() }
	];

	function revoke(id: string) {
		sessions = sessions.filter((s) => s.id !== id);
		notify('success', 'Session revoked.');
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
			<input id="new-password" class="control" type="password" placeholder="At least 12 characters" />
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
