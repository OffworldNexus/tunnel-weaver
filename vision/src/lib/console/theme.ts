/** The console theme preference: follow the OS, or force light/dark. */
import { writable } from 'svelte/store';

export type Theme = 'auto' | 'light' | 'dark';

const KEY = 'tw-vision-theme';

function initial(): Theme {
	if (typeof localStorage === 'undefined') {
		return 'auto';
	}
	const stored = localStorage.getItem(KEY);
	return stored === 'light' || stored === 'dark' ? stored : 'auto';
}

export const theme = writable<Theme>(initial());

theme.subscribe((value) => {
	if (typeof document === 'undefined') {
		return;
	}
	if (value === 'auto') {
		document.documentElement.removeAttribute('data-theme');
	} else {
		document.documentElement.setAttribute('data-theme', value);
	}
	try {
		localStorage.setItem(KEY, value);
	} catch {
		// Private mode: the attribute still applies for this session.
	}
});

export function cycleTheme(): void {
	theme.update((t) => (t === 'auto' ? 'light' : t === 'light' ? 'dark' : 'auto'));
}
