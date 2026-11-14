// @ts-check
import eslint from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';

export default defineConfig(
  { ignores: ['dist/', 'coverage/', 'node_modules/'] },
  eslint.configs.recommended,
  tseslint.configs.strictTypeChecked,
  tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      eqeqeq: ['error', 'always'],
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-import-type-side-effects': 'error',
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
    },
  },
  {
    // Library code must never log (tokens, recovery codes and keys are secrets).
    files: ['src/**/*.ts'],
    rules: {
      'no-console': 'error',
      'no-restricted-globals': [
        'error',
        { name: 'localStorage', message: 'Secrets must never be stored in Web Storage.' },
        { name: 'sessionStorage', message: 'Secrets must never be stored in Web Storage.' },
      ],
      'no-restricted-properties': [
        'error',
        { object: 'document', property: 'cookie', message: 'Cookies are never used.' },
        {
          object: 'window',
          property: 'localStorage',
          message: 'Secrets must never be stored in Web Storage.',
        },
        {
          object: 'window',
          property: 'sessionStorage',
          message: 'Secrets must never be stored in Web Storage.',
        },
        {
          object: 'globalThis',
          property: 'localStorage',
          message: 'Secrets must never be stored in Web Storage.',
        },
        {
          object: 'globalThis',
          property: 'sessionStorage',
          message: 'Secrets must never be stored in Web Storage.',
        },
      ],
    },
  },
  {
    files: ['**/*.js'],
    extends: [tseslint.configs.disableTypeChecked],
  },
);
