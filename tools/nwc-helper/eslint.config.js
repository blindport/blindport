import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    files: ["**/*.ts"],
    languageOptions: { parserOptions: { projectService: true } },
    rules: {
      "no-console": "error",
      "@typescript-eslint/no-confusing-void-expression": "off"
    }
  },
  {
    files: ["src/main.ts"],
    rules: {
      "no-console": "off",
      "@typescript-eslint/no-unnecessary-condition": "off"
    }
  },
  {
    files: ["test/**/*.ts"],
    rules: { "@typescript-eslint/require-await": "off" }
  },
  { ignores: ["dist/**"] },
);
