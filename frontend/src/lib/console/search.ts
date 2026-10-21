/**
 * The machines search query, shared by the top-bar field and the machines
 * list's own filter, so the two are one query rather than two.
 */
import { writable } from 'svelte/store';

export const searchQuery = writable('');
