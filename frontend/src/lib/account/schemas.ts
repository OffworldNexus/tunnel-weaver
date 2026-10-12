/**
 * Valibot schemas shared by every account form.
 *
 * These power Superforms' client-side validation. The relay validates again
 * and authoritatively; the client checks are guidance so the user gets
 * immediate field-level feedback.
 */
import * as v from 'valibot';

const EMAIL_MAX = 254;
const NAME_MAX = 80;

export const emailSchema = v.pipe(
	v.string('Enter your email address.'),
	v.trim(),
	v.nonEmpty('Enter your email address.'),
	v.maxLength(EMAIL_MAX, 'That email address is too long.'),
	v.email('Enter a valid email address, like you@example.com.')
);

export const nameSchema = v.pipe(
	v.string('Enter your name.'),
	v.trim(),
	v.nonEmpty('Enter your name.'),
	v.maxLength(NAME_MAX, `Keep your name under ${NAME_MAX} characters.`)
);

export const signInSchema = v.object({
	email: emailSchema,
	password: v.pipe(v.string('Enter your password.'), v.nonEmpty('Enter your password.'))
});

export const signUpSchema = v.object({
	name: nameSchema,
	email: emailSchema
});

export const resendSchema = v.object({
	flow: v.pipe(v.string(), v.nonEmpty())
});

/** The reset-request form: a bare address, like the sign-up step. */
export const resetRequestSchema = v.object({
	email: emailSchema
});

/**
 * The minimum length comes from `/api/account/config`, which may arrive after
 * the form is created, so it is read lazily through a getter.
 */
export function setPasswordSchema(minLength: () => number) {
	return v.object({
		password: v.pipe(
			v.string('Choose a password.'),
			v.check(
				(value) => value.length >= minLength(),
				() => `Use at least ${minLength()} characters.`
			),
			v.maxLength(1024, 'That password is too long.')
		)
	});
}

export type SignInForm = v.InferOutput<typeof signInSchema>;
export type SignUpForm = v.InferOutput<typeof signUpSchema>;
export type SetPasswordForm = v.InferOutput<ReturnType<typeof setPasswordSchema>>;
export type ResendForm = v.InferOutput<typeof resendSchema>;
export type ResetRequestForm = v.InferOutput<typeof resetRequestSchema>;
