<script lang="ts">
	/**
	 * The signed-in console shell: a role-aware sidebar, a top bar with global
	 * search and live controls, and a wide content column.
	 */
	import WeaverMark from '#lib/brand/WeaverMark.svelte';
	import {
		activeOrg,
		activePerson,
		clearSelection,
		current,
		live,
		review,
		selectedPersonId,
		signOut,
		visibleReview
	} from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';

	import Avatar from './Avatar.svelte';
	import { navFor, type NavItem } from './nav';
	import SearchField from './SearchField.svelte';
	import ThemeToggle from './ThemeToggle.svelte';
	import Toggle from './Toggle.svelte';

	export let title = '';
	export let subtitle = '';
	export let crumbs: { label: string; href?: string }[] = [];

	let mobileOpen = false;

	$: sections = $current ? navFor($current.role, $activeOrg, $activePerson) : [];
	$: fleetPending = $review.filter((r) => r.verdict === 'pending').length;
	$: orgPending = $activeOrg
		? $review.filter((r) => r.orgId === $activeOrg.id && r.verdict === 'pending').length
		: 0;
	$: pending = $visibleReview.filter((r) => r.verdict === 'pending').length;
	$: reviewHref =
		$current?.role === 'super_admin' && !$activeOrg ? '/app/admin/review' : '/app/org/review';
	$: hrefs = sections.flatMap((section) => section.items.map((item) => item.href));
	function activeFor(pathname: string, allHrefs: string[]): string | undefined {
		return allHrefs
			.filter(
				(href) =>
					pathname === href ||
					(href !== '/app' && href !== '/app/org' && pathname.startsWith(`${href}/`))
			)
			.sort((a, b) => b.length - a.length)[0];
	}

	function onNavClick(item: NavItem) {
		mobileOpen = false;
		if (item.scope === 'fleet') {
			clearSelection();
		} else if (item.scope === 'org') {
			selectedPersonId.set('');
		}
	}

	async function doSignOut() {
		signOut();
		await goto('/sign-in');
	}
</script>

<div class="shell" class:shell--open={mobileOpen}>
	<aside class="sidebar">
		<a class="brand" href="/">
			<span class="brand__mark"><WeaverMark /></span>
			<span class="brand__text">
				<span class="brand__word">Tunnel Weaver</span>
				<span class="brand__tag">console</span>
			</span>
		</a>

		<nav class="nav" aria-label="Console">
			{#each sections as section (section.scope + ':' + section.title)}
				<div
					class="nav__section"
					class:nav__section--sub={($current?.role === 'super_admin' &&
						(section.scope === 'org' || section.scope === 'person')) ||
						($current?.role === 'org_admin' && section.scope === 'person')}
				>
					<p class="nav__title">{section.title}</p>
					{#each section.items as item (item.href)}
						{@const isCurrent = item.href === activeFor(page.url.pathname, hrefs)}
						<a
							class="nav__link"
							class:active={isCurrent}
							href={item.href}
							aria-current={isCurrent ? 'page' : undefined}
							on:click={() => onNavClick(item)}
						>
							<Icon name={item.icon} size={18} />
							<span class="nav__label">{item.label}</span>
							{#if item.badge === 'fleet-review' && fleetPending > 0}
								<span class="nav__badge">{fleetPending}</span>
							{:else if item.badge === 'org-review' && orgPending > 0}
								<span class="nav__badge">{orgPending}</span>
							{/if}
						</a>
					{/each}
				</div>
			{/each}
		</nav>

		<div class="sidebar__foot">
			{#if $current}
				<div class="who">
					<Avatar name={$current.person.name} size={36} />
					<div class="who__text">
						<span class="who__name">{$current.person.name}</span>
						<span class="who__role">
							{#if $current.role === 'super_admin'}
								Super admin
							{:else if $current.role === 'org_admin'}
								Org admin · {$current.org?.name ?? ''}
							{:else}
								User · {$current.org?.name ?? ''}
							{/if}
						</span>
					</div>
				</div>
			{/if}
			<button class="signout" type="button" on:click={doSignOut}>
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
		on:click={() => (mobileOpen = false)}
	></button>

	<div class="main">
		<header class="topbar">
			<button
				class="topbar__burger"
				type="button"
				aria-label="Open navigation"
				on:click={() => (mobileOpen = true)}
			>
				<Icon name="list" size={20} />
			</button>

			<div class="crumbs">
				{#each crumbs as crumb, i (crumb.label)}
					{#if crumb.href}
						<a href={crumb.href}>{crumb.label}</a>
					{:else}
						<span aria-current="page">{crumb.label}</span>
					{/if}
					{#if i < crumbs.length - 1}<span class="crumbs__sep" aria-hidden="true">/</span>{/if}
				{/each}
			</div>

			<div class="topbar__search">
				<SearchField />
			</div>

			<div class="topbar__tools">
				<Toggle bind:checked={$live} compact label={$live ? 'Live' : 'Paused'} />

				{#if $current?.role !== 'user'}
					<a class="icon-btn" href={reviewHref} aria-label="Review queue" title="Review queue">
						<Icon name="shield" size={18} />
						{#if pending > 0}<span class="icon-btn__badge">{pending}</span>{/if}
					</a>
				{/if}
			</div>
		</header>

		<main class="content" id="main">
			<div class="page-head">
				<div class="page-head__text">
					{#if title}<h1 class="page-head__title">{title}</h1>{/if}
					{#if subtitle}<p class="page-head__sub">{subtitle}</p>{/if}
				</div>
				<div class="page-head__actions"><slot name="actions" /></div>
			</div>
			<slot />
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

	.nav__section--sub {
		padding-left: 10px;
		border-left: 2px solid var(--tw-accent);
	}

	.nav__section--sub .nav__title {
		color: var(--tw-accent);
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

	.nav__badge {
		min-width: 20px;
		height: 20px;
		padding: 0 6px;
		display: grid;
		place-items: center;
		border-radius: 999px;
		background: var(--tw-danger);
		color: var(--tw-well);
		font-family: var(--tw-mono);
		font-size: 11px;
		font-weight: 700;
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

	.topbar__tools {
		display: flex;
		align-items: center;
		gap: 12px;
	}

	.icon-btn {
		position: relative;
		display: grid;
		place-items: center;
		width: 36px;
		height: 36px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
		color: var(--tw-text);
	}

	.icon-btn:hover {
		background: var(--tw-raised);
	}

	.icon-btn__badge {
		position: absolute;
		top: -6px;
		right: -6px;
		min-width: 17px;
		height: 17px;
		padding: 0 4px;
		display: grid;
		place-items: center;
		border-radius: 999px;
		background: var(--tw-danger);
		color: var(--tw-well);
		font-family: var(--tw-mono);
		font-size: 10px;
		font-weight: 700;
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
			display: none;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.sidebar,
		.scrim {
			transition: none;
		}
	}
</style>
