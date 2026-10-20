import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import sonarjs from 'eslint-plugin-sonarjs';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';
import ts from 'typescript-eslint';

/** @type {import('eslint').Linter.Config[]} */
export default [
	js.configs.recommended,
	...ts.configs.recommended,
	...svelte.configs['flat/recommended'],
	sonarjs.configs.recommended,
	prettier,
	...svelte.configs['flat/prettier'],
	{
		plugins: {
			'simple-import-sort': simpleImportSort
		},
		rules: {
			'simple-import-sort/imports': 'error',
			'simple-import-sort/exports': 'error',
			'sonarjs/void-use': 'off',
			'no-plusplus': 'error',
			curly: 'error'
		}
	},
	{
		languageOptions: {
			globals: {
				...globals.browser
			}
		}
	},
	{
		files: ['scripts/**/*.mjs'],
		languageOptions: {
			globals: {
				...globals.node
			}
		}
	},
	// Type-aware linting for every file the TS project service can see.
	{
		files: ['**/*.ts', '**/*.svelte', '*.js', '*.mjs', '*.cjs'],
		languageOptions: {
			parserOptions: {
				// The SPA's tsconfig has no Node types, so this file is linted
				// through the default project instead of being type-checked with it.
				projectService: {
					allowDefaultProject: ['eslint.config.js']
				},
				tsconfigRootDir: import.meta.dirname,
				extraFileExtensions: ['.svelte']
			}
		}
	},
	...ts.configs.recommendedTypeChecked.map((config) => ({
		...config,
		files: ['**/*.ts']
	})),
	// Type-checked rules for Svelte files, without overriding the Svelte parser.
	{
		files: ['**/*.svelte'],
		languageOptions: {
			parserOptions: {
				parser: ts.parser
			}
		},
		rules: {
			...ts.configs.recommendedTypeChecked.reduce(
				(acc, config) => ({ ...acc, ...config.rules }),
				{}
			),
			'prefer-const': 'off'
		}
	},
	{
		rules: {
			'@typescript-eslint/only-throw-error': 'off'
		}
	},
	{
		ignores: ['build/', '.svelte-kit/', 'node_modules/']
	}
];
