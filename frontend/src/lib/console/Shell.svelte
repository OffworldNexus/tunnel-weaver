<script lang="ts">
	/**
	 * The signed-in console shell: the sidebar (brand, sections, and the
	 * who/sign-out/theme foot), a top bar with breadcrumbs and the machines
	 * search, and a wide content column whose head comes from the page's
	 * `setMeta`. The session guard lives in the `/app` layout above it.
	 */
	import type { Snippet } from 'svelte';

	import { api } from '#lib/account/api';
	import { notify } from '#lib/account/notices';
	import { me } from '#lib/app/me.svelte';
	import WeaverMark from '#lib/brand/WeaverMark.svelte';
	import BirdAvatar from '#lib/console/BirdAvatar.svelte';
	import { navSections } from '#lib/console/nav';
	import SearchField from '#lib/console/SearchField.svelte';
	import ThemeToggle from '#lib/console/ThemeToggle.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';

	export interface Props {
		title?: string;
		subtitle?: string;
		crumbs?: { label: string; href?: string }[];
		actions?: Snippet;
		children?: Snippet;
	}

	let { title = '', subtitle = '', crumbs = [], actions, children }: Props = $props();

	const sections = navSections();
	const hrefs = sections.flatMap((section) => section.items.map((item) => item.href));

	let mobileOpen = $state(false);
	let signingOut = $state(false);

	/** The longest nav href the current path sits under. */
	function activeFor(pathname: string): string | undefined {
		return hrefs
			.filter((href) => pathname === href || (href !== '/app' && pathname.startsWith(`${href}/`)))
			.sort((a, b) => b.length - a.length)[0];
	}

	async function doSignOut() {
		signingOut = true;
		const res = await api('/api/account/logout', {});
		signingOut = false;
		if (!res.ok) {
			notify('error', res.error ?? 'We could not sign you out. Please try again.');
			return;
		}
		notify('success', 'You have been signed out.');
		await goto(resolve('/sign-in'));
	}
</script>

<svelte:head>
	<title>{title ? `${title} · Tunnel Weaver` : 'Console · Tunnel Weaver'}</title>
</svelte:head>

<div class="shell" class:shell--open={mobileOpen}>
	<aside class="sidebar">
		<a class="brand" href={resolve('/')}>
			<span class="brand__mark"><WeaverMark /></span>
			<span class="brand__text">
				<span class="brand__word">Tunnel Weaver</span>
				<span class="brand__tag">console</span>
			</span>
		</a>

		<nav class="nav" aria-label="Console">
			{#each sections as section (section.title)}
				<div class="nav__section">
					<p class="nav__title">{section.title}</p>
					{#each section.items as item (item.href)}
						{@const isCurrent = item.href === activeFor(page.url.pathname)}
						<!-- eslint-disable svelte/no-navigation-without-resolve -- nav hrefs are literal route paths from nav.ts; the app has no base path -->
						<a
							class="nav__link"
							class:active={isCurrent}
							href={item.href}
							aria-current={isCurrent ? 'page' : undefined}
							onclick={() => (mobileOpen = false)}
						>
							<Icon name={item.icon} size={18} />
							<span class="nav__label">{item.label}</span>
						</a>
						<!-- eslint-enable svelte/no-navigation-without-resolve -->
					{/each}
				</div>
			{/each}
		</nav>

		<div class="sidebar__foot">
			{#if me.value}
				{@const account = me.value}
				<div class="who">
					<BirdAvatar size={36} />
					<div class="who__text">
						<span class="who__name">{account.name}</span>
						<span class="who__role">{account.email || 'Signed in'}</span>
					</div>
				</div>
			{/if}
			<button class="signout" type="button" disabled={signingOut} onclick={doSignOut}>
				<Icon name="power" size={16} /> Sign out
			</button>
			<div class="sidebar__theme">
				<ThemeToggle variant="footer" />
			</div>
		</div>
	</aside>

	<button
		class="scrim"
		type="button"
		aria-label="Close navigation"
		onclick={() => (mobileOpen = false)}
	></button>

	<div class="main">
		<header class="topbar">
			<button
				class="topbar__burger"
				type="button"
				aria-label="Open navigation"
				onclick={() => (mobileOpen = true)}
			>
				<Icon name="list" size={20} />
			</button>

			<div class="crumbs">
				{#each crumbs as crumb, i (crumb.label)}
					{#if crumb.href}
						<!-- eslint-disable svelte/no-navigation-without-resolve -- crumb hrefs are literal route paths handed in by the page -->
						<a href={crumb.href}>{crumb.label}</a>
						<!-- eslint-enable svelte/no-navigation-without-resolve -->
					{:else}
						<span aria-current="page">{crumb.label}</span>
					{/if}
					{#if i < crumbs.length - 1}<span class="crumbs__sep" aria-hidden="true">/</span>{/if}
				{/each}
			</div>

			<div class="topbar__search">
				<SearchField />
			</div>
		</header>

		<main class="content" id="main">
			<div class="page-head">
				<div class="page-head__text">
					{#if title}<h1 class="page-head__title">{title}</h1>{/if}
					{#if subtitle}<p class="page-head__sub">{subtitle}</p>{/if}
				</div>
				<div class="page-head__actions">{@render actions?.()}</div>
			</div>
			{@render children?.()}
		</main>
	</div>
</div>

<style lang="scss">
	.shell {
		display: grid;
		grid-template-columns: 264px 1fr;
		min-height: 100svh;
		background: var(--tw-deck);
	}

	/* ---- sidebar ---- */
	.sidebar {
		display: flex;
		flex-direction: column;
		gap: 18px;
		padding: 18px 14px;
		border-right: 1.5px solid var(--tw-border);
		background: color-mix(in srgb, var(--tw-well) 70%, var(--tw-deck));
		position: sticky;
		top: 0;
		height: 100svh;
		overflow-y: auto;
	}

	.brand {
		display: flex;
		align-items: center;
		gap: 10px;
		color: inherit;
		text-decoration: none;
		padding: 4px 6px;
	}

	.brand:hover {
		text-decoration: none;
	}

	.brand__mark {
		width: 30px;
		height: 31px;
		flex: none;
	}

	.brand__mark :global(svg) {
		display: block;
		width: 100%;
		height: 100%;
	}

	.brand__text {
		display: flex;
		flex-direction: column;
		line-height: 1.15;
	}

	.brand__word {
		font-family: var(--tw-heading);
		font-weight: 700;
		font-size: 16px;
	}

	.brand__tag {
		font-family: var(--tw-mono);
		font-size: 11px;
		letter-spacing: 0.22em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.nav {
		display: flex;
		flex-direction: column;
		gap: 18px;
		flex: 1 1 auto;
	}

	.nav__section {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.nav__title {
		padding: 0 8px 6px;
		font-size: 11px;
		font-weight: 700;
		letter-spacing: 0.1em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.nav__link {
		display: flex;
		align-items: center;
		gap: 10px;
		min-height: 40px;
		padding: 0 10px;
		border-radius: var(--tw-radius);
		color: var(--tw-text);
		text-decoration: none;
		font-size: 14px;
		font-weight: 600;
	}

	.nav__link:hover {
		text-decoration: none;
		background: color-mix(in srgb, var(--tw-text) 7%, transparent);
	}

	.nav__link.active {
		background: var(--tw-accent);
		color: var(--tw-well);
	}

	.nav__label {
		flex: 1 1 auto;
	}

	.sidebar__foot {
		display: flex;
		flex-direction: column;
		gap: 10px;
		padding-top: 14px;
		border-top: 1.5px solid var(--tw-border);
	}

	.sidebar__theme {
		display: flex;
		margin-top: 2px;
		padding-top: 10px;
		border-top: 1px solid var(--tw-line-hair);
	}

	.who {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.who__text {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}

	.who__name {
		font-weight: 700;
		font-size: 14px;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.who__role {
		color: var(--tw-muted);
		font-size: 12px;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.signout {
		display: flex;
		align-items: center;
		gap: 8px;
		min-height: 36px;
		padding: 0 10px;
		border: 0;
		border-radius: var(--tw-radius);
		background: none;
		color: var(--tw-muted);
		font: 700 13px/1 var(--tw-sans);
		cursor: pointer;
	}

	.signout:hover {
		color: var(--tw-danger);
		background: color-mix(in srgb, var(--tw-danger) 10%, transparent);
	}

	.signout:disabled {
		cursor: progress;
		opacity: 0.6;
	}

	/* ---- main ---- */
	.main {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}

	.topbar {
		position: sticky;
		top: 0;
		z-index: 20;
		display: flex;
		align-items: center;
		gap: 14px;
		min-height: 60px;
		padding: 8px 20px;
		border-bottom: 1.5px solid var(--tw-border);
		background: color-mix(in srgb, var(--tw-deck) 88%, transparent);
		backdrop-filter: blur(8px);
	}

	.topbar__burger {
		display: none;
	}

	.crumbs {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 13px;
		color: var(--tw-muted);
		min-width: 0;
	}

	.crumbs a {
		color: var(--tw-muted);
		text-decoration: none;
	}

	.crumbs a:hover {
		color: var(--tw-text);
		text-decoration: underline;
	}

	.crumbs [aria-current='page'] {
		color: var(--tw-text);
		font-weight: 700;
	}

	.crumbs__sep {
		opacity: 0.5;
	}

	.topbar__search {
		margin-left: auto;
		flex: 1 1 auto;
		display: flex;
		justify-content: flex-end;
		min-width: 0;
	}

	.content {
		width: 100%;
		max-width: 1440px;
		margin: 0 auto;
		padding: 22px 20px 64px;
		display: flex;
		flex-direction: column;
		gap: 18px;
	}

	.page-head {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-end;
		justify-content: space-between;
		gap: 12px;
	}

	.page-head__title {
		font-size: 28px;
		line-height: 1.15;
	}

	.page-head__sub {
		margin-top: 4px;
		color: var(--tw-muted);
		font-size: 15px;
	}

	.page-head__actions {
		display: flex;
		flex-wrap: wrap;
		gap: 10px;
	}

	/* ---- responsive ---- */
	.scrim {
		display: none;
		border: 0;
		padding: 0;
	}

	@media (max-width: 980px) {
		.shell {
			grid-template-columns: 1fr;
		}

		.sidebar {
			position: fixed;
			z-index: 40;
			inset: 0 auto 0 0;
			width: 280px;
			transform: translateX(-100%);
			transition: transform 180ms ease;
			box-shadow: var(--tw-shadow);
		}

		.shell--open .sidebar {
			transform: none;
		}

		.scrim {
			display: block;
			position: fixed;
			inset: 0;
			z-index: 30;
			background: rgb(11 6 4 / 0.4);
			opacity: 0;
			pointer-events: none;
			transition: opacity 180ms ease;
		}

		.shell--open .scrim {
			opacity: 1;
			pointer-events: auto;
		}

		.topbar__burger {
			display: grid;
			place-items: center;
			width: 38px;
			height: 38px;
			border: 1.5px solid var(--tw-border);
			border-radius: var(--tw-radius);
			background: var(--tw-well);
			color: var(--tw-text);
			cursor: pointer;
		}

		.topbar__search {
			flex: 1 1 auto;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.sidebar,
		.scrim {
			transition: none;
		}
	}
</style>
