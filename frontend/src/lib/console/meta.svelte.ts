/**
 * The shell reads its title, subtitle and breadcrumbs from here. Pages call
 * `setMeta()` during initialisation; the layout reads the state into `<Shell>`.
 */

export interface Crumb {
	label: string;
	href?: string;
}

export interface Meta {
	title: string;
	subtitle: string;
	crumbs: Crumb[];
}

export const meta = $state<Meta>({ title: '', subtitle: '', crumbs: [] });

export function setMeta(next: Partial<Meta>): void {
	meta.title = next.title ?? '';
	meta.subtitle = next.subtitle ?? '';
	meta.crumbs = next.crumbs ?? [];
}
