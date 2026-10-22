import type { Org, Person, Role } from '#lib/mock/types';
import type { IconName } from '#lib/ui/icons';

export interface NavItem {
	label: string;
	href: string;
	icon: IconName;
	/** Which level of the hierarchy clicking this link resets to. */
	scope?: 'fleet' | 'org' | 'person' | 'account';
	/** Optional badge count kind. */
	badge?: 'fleet-review' | 'org-review';
}

export interface NavSection {
	title: string;
	scope: 'fleet' | 'org' | 'person' | 'account';
	items: NavItem[];
}

function orgSection(org: Org): NavSection {
	return {
		title: org.name,
		scope: 'org',
		items: [
			{ label: 'Overview', href: '/app/org', icon: 'building', scope: 'org' },
			{ label: 'Users', href: '/app/org/users', icon: 'users', scope: 'org' },
			{
				label: 'Review queue',
				href: '/app/org/review',
				icon: 'shield',
				scope: 'org',
				badge: 'org-review'
			},
			{ label: 'Settings', href: '/app/org/settings', icon: 'settings', scope: 'org' }
		]
	};
}

function personSection(person: Person, isSelf: boolean): NavSection {
	return {
		title: isSelf ? 'Your machines' : person.name,
		scope: 'person',
		items: [
			{
				label: 'Overview',
				href: isSelf ? '/app' : `/app/people/${person.id}`,
				icon: 'gauge',
				scope: 'person'
			},
			{ label: 'Machines', href: '/app/machines', icon: 'machine', scope: 'person' }
		]
	};
}

/**
 * The sidebar tree, scoped to the viewer's role and whichever organisation /
 * user is currently selected in the drill-down.
 */
export function navFor(
	role: Role,
	activeOrg: Org | null,
	activePerson: Person | null
): NavSection[] {
	if (role === 'user') {
		return [
			...(activePerson ? [personSection(activePerson, true)] : []),
			{
				title: 'Account',
				scope: 'account',
				items: [
					{ label: 'Profile', href: '/app/account', icon: 'users', scope: 'account' },
					{ label: 'Security', href: '/app/security', icon: 'lock', scope: 'account' },
					{ label: 'Create organisation', href: '/app/new-org', icon: 'building', scope: 'account' }
				]
			}
		];
	}

	if (role === 'org_admin') {
		return [
			...(activeOrg ? [orgSection(activeOrg)] : []),
			...(activePerson ? [personSection(activePerson, false)] : []),
			{
				title: 'Account',
				scope: 'account',
				items: [
					{ label: 'Profile', href: '/app/account', icon: 'users', scope: 'account' },
					{ label: 'Security', href: '/app/security', icon: 'lock', scope: 'account' }
				]
			}
		];
	}

	// Super admin: starts with Fleet only; selecting an org reveals that org's
	// native menu, and selecting a user inside it reveals the user's menu.
	return [
		{
			title: 'Fleet',
			scope: 'fleet',
			items: [
				{ label: 'Overview', href: '/app', icon: 'gauge', scope: 'fleet' },
				{ label: 'Organisations', href: '/app/admin/orgs', icon: 'building', scope: 'fleet' },
				{
					label: 'Review queue',
					href: '/app/admin/review',
					icon: 'shield',
					scope: 'fleet',
					badge: 'fleet-review'
				},
				{ label: 'Thresholds', href: '/app/admin/settings', icon: 'settings', scope: 'fleet' }
			]
		},
		...(activeOrg ? [orgSection(activeOrg)] : []),
		...(activePerson ? [personSection(activePerson, false)] : []),
		{
			title: 'Account',
			scope: 'account',
			items: [
				{ label: 'Profile', href: '/app/account', icon: 'users', scope: 'account' },
				{ label: 'Security', href: '/app/security', icon: 'lock', scope: 'account' }
			]
		}
	];
}
