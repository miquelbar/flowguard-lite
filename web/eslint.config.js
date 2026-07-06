import js from "@eslint/js";
import globals from "globals";

export default [
    js.configs.recommended,
    {
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: "module",
            globals: {
                ...globals.browser,
                ...globals.es2021
            }
        },
        rules: {
            "no-unused-vars": ["warn", { 
                "vars": "all",
                "args": "none",
                "ignoreRestSiblings": true
            }],
            "no-undef": "error"
        }
    }
];
