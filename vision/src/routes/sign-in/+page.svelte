<script lang="ts">
	/** Mock sign-in: pick a persona to explore the console as. */
	import Avatar from '#lib/console/Avatar.svelte';
	import { orgById, people, signIn } from '#lib/mock/store';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';

	$: demos = $people.filter((p) => p.demo);

	const roleCopy: Record<string, string> = {
		super_admin: 'Manages organisations, fleet bandwidth and the global abuse review queue. Owns no machines.',
		org_admin: 'Manages one organisation: users, bandwidth breakdown and the org review queue. Owns no machines.',
		user: 'Owns paired machines and service tunnels; inspects live traffic and HTTP query logs.'
	};

	async function enter(personId: string) {
		signIn(personId);
		const chosen = $people.find((p) => p.id === personId);
		await goto(chosen?.role === 'org_admin' ? '/app/org' : '/app');
	}
</script>

<svelte:head>
	<title>Sign in · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="signin-title">
	<h1 id="signin-title">Sign in</h1>
	<p class="lede">This is a design preview. Every screen is mocked — choose a role to explore.</p>

	<ul class="personas">
		{#each demos as person (person.id)}
			<li>
				<button class="persona" type="button" on:click={() => enter(person.id)}>
					<span class="persona__head">
						<Avatar name={person.name} size={40} />
						<span class="persona__id">
							<span class="persona__name">{person.name}</span>
							<span class="persona__email">{person.email}</span>
						</span>
					</span>
					<span class="persona__role">
						{orgById(person.orgId)?.name ?? 'Global fleet operator'}
					</span>
					<span class="persona__copy">{roleCopy[person.role]}</span>
					<span class="persona__cta">Enter as {person.role.replace('_', ' ')} →</span>
				</button>
			</li>
		{/each}
	</ul>

	<div class="or"><span>or</span></div>

	<form class="form" on:submit|preventDefault={() => enter('usr_sam')}>
		<div class="field">
			<label for="email">Email</label>
			<input id="email" type="email" placeholder="you@example.com" />
		</div>
		<div class="field">
			<label for="password">Password</label>
			<input id="password" type="password" placeholder="••••••••" />
		</div>
		<Keycap type="submit" wide>Continue as Sam Okafor</Keycap>
	</form>
</Page>

<style lang="scss">
	@use 'mixins' as *;

	.lede {
		margin-top: 16px;
	}

	.personas {
		list-style: none;
		margin: 24px 0 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.persona {
		@include cut-panel(12px, var(--tw-well), var(--tw-border), 1.5px);
		display: flex;
		flex-direction: column;
		gap: 6px;
		width: 100%;
		padding: 16px;
		text-align: left;
		cursor: pointer;
		color: var(--tw-text);
		font: inherit;
	}

	.persona:hover {
		--tw-border: var(--tw-accent);
	}

	.persona__head {
		display: flex;
		align-items: center;
		gap: 12px;
	}

	.persona__id {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}

	.persona__name {
		font-family: var(--tw-heading);
		font-size: 16px;
		font-weight: 700;
	}

	.persona__email {
		color: var(--tw-muted);
		font-size: 13px;
	}

	.persona__role {
		margin-top: 6px;
		font-family: var(--tw-mono);
		font-size: 11px;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--tw-accent);
	}

	.persona__copy {
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.5;
	}

	.persona__cta {
		margin-top: 4px;
		font-weight: 700;
		font-size: 13px;
		color: var(--tw-accent);
	}

	.or {
		display: flex;
		align-items: center;
		gap: 12px;
		margin: 24px 0 4px;
		color: var(--tw-muted);
		font-size: 12px;
		text-transform: uppercase;
		letter-spacing: 0.14em;
	}

	.or::before,
	.or::after {
		content: '';
		flex: 1;
		height: 1px;
		background: var(--tw-border);
	}
</style>
