import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";

const eslintConfig = defineConfig([
  js.configs.recommended,
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      }
    },
    rules: {
      "no-unused-vars": "warn",
      "no-console": "off",
    }
  },
  globalIgnores([
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    "node_modules/**"
  ]),
]);

export default eslintConfig;
