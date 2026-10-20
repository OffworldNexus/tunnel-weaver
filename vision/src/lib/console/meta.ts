/**
 * The shell reads its title, subtitle and breadcrumbs from here. Pages call
 * `setMeta()` during initialisation; the layout passes the store to `<Shell>`.
 */
import { writable } from 'svelte/store';

export interface Crumb {
	label: string;
	href?: string;
}

export interface Meta {
	title: string;
	subtitle: string;
	crumbs: Crumb[];
}

export const meta = writable<Meta>({ title: '', subtitle: '', crumbs: [] });

export function setMeta(next: Partial<Meta>): void {
	meta.set({ title: '', subtitle: '', crumbs: [], ...next });
}
