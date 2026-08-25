'use strict';

const js = require('@eslint/js');
const globals = require('globals');

// Correctness-focused rules. The goal here is catching real defects (typos,
// dead code, accidental globals, loose equality bugs), not enforcing a house
// formatting style — this project has no existing formatter/style guide and
// this config is not meant to introduce one.
const CORRECTNESS_RULES = {
  'no-undef': 'error',
  'no-unused-vars': ['error', {
    args: 'after-used',
    argsIgnorePattern: '^_',
    varsIgnorePattern: '^_',
    caughtErrors: 'none',
    // `const { omit, ...rest } = obj` to drop fields is used deliberately in
    // a few places (e.g. stripping DB-internal columns before an API export);
    // the discarded names are documentation, not dead code.
    ignoreRestSiblings: true
  }],
  'no-unreachable': 'error',
  'no-constant-condition': ['error', { checkLoops: false }],
  'no-dupe-keys': 'error',
  'no-dupe-args': 'error',
  'no-fallthrough': 'error',
  'no-self-assign': 'error',
  'no-useless-catch': 'error',
  'no-var': 'error',
  eqeqeq: ['error', 'smart'],
  curly: ['error', 'multi-line'],
  'prefer-const': ['warn', { destructuring: 'all' }],
  // @eslint/js's recommended preset added this in a recent major version.
  // SHAM consistently rethrows caught errors as a new, more specific Error
  // with a human-readable message (not an Error.cause chain), across ~20
  // existing catch blocks. Retrofitting `cause` everywhere would be exactly
  // the kind of broad, low-value mechanical edit this project's static
  // analysis is not meant to force — see the "Error handling" guidance this
  // config was introduced under. Left off deliberately, not by omission.
  'preserve-caught-error': 'off'
};

module.exports = [
  {
    ignores: [
      'node_modules/**',
      'data/**',
      'sham-data/**',
      'coverage/**',
      'package-lock.json',
      // Vendored/generated geo data, not hand-written or reviewed as code.
      'public/world-map.js',
      // Sample/documentation code shipped for users, not part of SHAM itself.
      'examples/**'
    ]
  },

  // Node.js backend: control plane, CLI, and the privileged runtime agent.
  {
    files: ['src/**/*.js', 'bin/**/*.js', 'runtime-agent/**/*.js', 'scripts/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: { ...globals.node }
    },
    rules: {
      ...js.configs.recommended.rules,
      ...CORRECTNESS_RULES
    }
  },

  // node:test files. Same Node environment; test bodies frequently leave
  // deliberately-unused destructured fixture values, which the shared
  // no-unused-vars settings above already tolerate via the `_` prefix.
  {
    files: ['test/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: { ...globals.node }
    },
    rules: {
      ...js.configs.recommended.rules,
      ...CORRECTNESS_RULES
    }
  },

  // Browser dashboard code. These are classic (non-module) <script> tags
  // loaded in a fixed order from public/index.html and intentionally share
  // one global scope (public/js/core.js defines `state`, `$`, `formatDate`,
  // top-level consts, etc. that later scripts use directly, and public/js/
  // files call each other's top-level functions the same way) — that is the
  // existing architecture, not a bug. Two rules cannot be enforced correctly
  // file-by-file as a result:
  //  - no-undef: a name defined in an earlier script is not "undefined" here.
  //  - no-unused-vars: a top-level const/function "unused" in this file may
  //    be exactly the API another script calls (verified concretely: an
  //    earlier pass of this config nearly deleted MAX_BROWSER_UPLOAD_FILES,
  //    a real upload-size guard used only from public/js/sites.js).
  // Both are disabled here rather than hand-maintaining a duplicate global
  // list. Other correctness rules (no-unreachable, no-dupe-keys, eqeqeq,
  // curly, no-fallthrough, ...) do not have this cross-file blind spot and
  // stay enabled.
  {
    files: ['public/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'script',
      globals: { ...globals.browser }
    },
    rules: {
      ...js.configs.recommended.rules,
      ...CORRECTNESS_RULES,
      'no-undef': 'off',
      'no-unused-vars': 'off'
    }
  }
];
