/**
 * Valibot schemas for the account forms: immediate field-level guidance. The
 * relay validates again, authoritatively.
 */
import * as v from 'valibot';

import { minPasswordLength } from '#lib/account/config.svelte';

const NAME_MAX = 80;

const email = v.pipe(
	v.string(),
	v.trim(),
	v.nonEmpty('Enter your email address.'),
	v.maxLength(254, 'That email address is too long.'),
	v.email('Enter a valid email address, like you@example.com.')
);

const required = (message: string) => v.pipe(v.string(), v.nonEmpty(message));

/** Read at validation time: the minimum arrives with the relay's config. */
const newPassword = v.pipe(
	v.string(),
	v.check(
		(value) => value.length >= minPasswordLength(),
		() => `Use at least ${minPasswordLength()} characters.`
	),
	v.maxLength(1024, 'That password is too long.')
);

export const signInSchema = v.object({ email, password: required('Enter your password.') });

/**
 * The emailed second-factor code (WVR-167): exactly six digits, the shape the
 * relay issues. Trimmed so a pasted code with a stray space still validates.
 */
export const verifyCodeSchema = v.object({
	code: v.pipe(
		v.string(),
		v.trim(),
		v.nonEmpty('Enter the code from your email.'),
		v.regex(/^\d{6}$/, 'The code is six digits.')
	)
});

export const signUpSchema = v.object({
	name: v.pipe(
		v.string(),
		v.trim(),
		v.nonEmpty('Enter your name.'),
		v.maxLength(NAME_MAX, `Keep your name under ${NAME_MAX} characters.`)
	),
	email
});

export const resetRequestSchema = v.object({ email });

export const setPasswordSchema = v.object({ password: newPassword });

export const changePasswordSchema = v.object({
	current_password: required('Enter your current password.'),
	new_password: newPassword
});
