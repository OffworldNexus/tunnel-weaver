/**
 * The console's sidebar tree.
 *
 * This console is single-person: a signed-in account and the machines it
 * pairs, with no organisations or roles beneath it. So the tree is one flat
 * pair of sections — the machines, and the account they belong to.
 */
import type { IconName } from '#lib/ui/icons';

export interface NavItem {
	label: string;
	href: string;
	icon: IconName;
}

export interface NavSection {
	title: string;
	items: NavItem[];
}

/** The sidebar sections for the signed-in person. */
export function navSections(): NavSection[] {
	return [
		{
			title: 'Your machines',
			items: [
				{ label: 'Overview', href: '/app', icon: 'gauge' },
				{ label: 'Machines', href: '/app/machines', icon: 'machine' }
			]
		},
		{
			title: 'Account',
			items: [{ label: 'Security', href: '/app/security', icon: 'lock' }]
		}
	];
}
