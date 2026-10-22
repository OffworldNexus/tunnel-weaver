/** A thin slice helper for the list surfaces that paginate client-side. */

export interface Page<T> {
	items: T[];
	/** The clamped, 1-based page actually returned. */
	page: number;
	pageCount: number;
	total: number;
	/** 1-based index of the first row, or 0 when empty. */
	from: number;
	/** 1-based index of the last row, or 0 when empty. */
	to: number;
}

export function paginate<T>(all: T[], page: number, size: number): Page<T> {
	const total = all.length;
	const pageCount = Math.max(1, Math.ceil(total / size));
	const current = Math.min(Math.max(1, page), pageCount);
	const start = (current - 1) * size;
	const items = all.slice(start, start + size);
	return {
		items,
		page: current,
		pageCount,
		total,
		from: total === 0 ? 0 : start + 1,
		to: start + items.length
	};
}

/** The page buttons to render: numbers with a `'gap'` marker for an ellipsis. */
export function pageWindow(page: number, pageCount: number): (number | 'gap')[] {
	if (pageCount <= 7) {
		return Array.from({ length: pageCount }, (_, i) => i + 1);
	}
	const out: (number | 'gap')[] = [1];
	const start = Math.max(2, page - 1);
	const end = Math.min(pageCount - 1, page + 1);
	if (start > 2) {
		out.push('gap');
	}
	for (let p = start; p <= end; p += 1) {
		out.push(p);
	}
	if (end < pageCount - 1) {
		out.push('gap');
	}
	out.push(pageCount);
	return out;
}
