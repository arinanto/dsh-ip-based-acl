import js from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";
import { defineConfig } from "eslint/config";
import eslintConfigPrettier from "eslint-config-prettier";

export default defineConfig(
  // 1. Compiled output and dependencies are not source
  {
    ignores: ["node_modules/**", "lib/**", "coverage/**"],
  },

  // 2. Recommended rule sets for plain JavaScript and TypeScript
  js.configs.recommended,
  ...tseslint.configs.recommended,

  // 3. Node-hosted TypeScript sources, type-aware through the project service
  {
    files: ["**/*.ts"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        projectService: true, // Enables full type-aware linting
      },
      globals: {
        ...globals.node, // Node globals (process, Buffer, etc.); this package never runs in a browser
      },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "warn",
    },
  },

  // 4. Must stay last: turns off ESLint rules that conflict with Prettier.
  eslintConfigPrettier,
);
