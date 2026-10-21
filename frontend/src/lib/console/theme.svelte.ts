/** The console theme preference: follow the OS, or force light/dark. */

export type Theme = 'auto' | 'light' | 'dark';

const KEY = 'tw-theme';

function initial(): Theme {
	if (typeof localStorage === 'undefined') {
		return 'auto';
	}
	const stored = localStorage.getItem(KEY);
	return stored === 'light' || stored === 'dark' ? stored : 'auto';
}

export const theme = $state<{ value: Theme }>({ value: initial() });

/**
 * Applies a preference to the document and remembers it. A module cannot use
 * `$effect`, so the DOM attribute and persistence happen here, in the setter.
 */
function apply(value: Theme): void {
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
}

export function setTheme(value: Theme): void {
	theme.value = value;
	apply(value);
}

export function cycleTheme(): void {
	if (theme.value === 'auto') {
		setTheme('light');
	} else if (theme.value === 'light') {
		setTheme('dark');
	} else {
		setTheme('auto');
	}
}

// The store applied the stored preference as soon as the module loaded (its
// `subscribe` ran the callback immediately); apply the initial value the same way.
apply(theme.value);
