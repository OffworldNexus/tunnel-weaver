import { superForm } from 'sveltekit-superforms';
import { valibot } from 'sveltekit-superforms/adapters';
import type * as v from 'valibot';

/**
 * A Superforms form for live, client-side validation, submitted by `submit` to
 * the JSON API instead of a form post. `submit` resolves to a form-wide error
 * message, or to nothing once it has moved on.
 */
export function jsonForm<S extends v.ObjectSchema<v.ObjectEntries, undefined>>(
	schema: S,
	initial: v.InferOutput<S>,
	submit: (data: v.InferOutput<S>) => Promise<string | null | void>
) {
	const sf = superForm(initial, {
		validators: valibot(schema),
		clearOnSubmit: 'errors-and-message',
		onSubmit: async ({ cancel }) => {
			cancel();
			const result = await sf.validateForm({ update: true });
			if (!result.valid) {
				return;
			}
			const error = await submit(result.data);
			if (error) {
				sf.message.set(error);
			}
		}
	});
	return sf;
}
