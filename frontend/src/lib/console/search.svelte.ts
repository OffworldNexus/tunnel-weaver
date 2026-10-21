/**
 * The machines search query, shared by the top-bar field and the machines
 * list's own filter, so the two are one query rather than two.
 */

export const search = $state({ q: '' });
