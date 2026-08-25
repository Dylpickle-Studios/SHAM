const { parentPort, workerData } = require('node:worker_threads');
if (!parentPort) throw new Error('This module must run inside a worker thread.');
const port = /** @type {import('node:worker_threads').MessagePort} */ (parentPort);
const CleanCSS = require('clean-css');
const { minify: minifyHtml } = require('html-minifier-terser');
// terser ships only ESM type declarations; this CJS require() still works
// at runtime (terser also publishes a CJS entry point), it just doesn't
// type-check cleanly against a `module: node16`+`require` combination.
// @ts-expect-error TS1479 -- see comment above.
const { minify: minifyJs } = require('terser');

function javascriptOptions({ minify, obfuscate, module = false }) {
  return {
    compress: minify ? {
      passes: obfuscate ? 2 : 1,
      // Avoid transformations that are more likely to surprise reflection-heavy code.
      unsafe: false,
      unsafe_arrows: false,
      unsafe_comps: false,
      unsafe_Function: false,
      unsafe_math: false,
      unsafe_methods: false,
      unsafe_proto: false,
      unsafe_regexp: false,
      unsafe_undefined: false
    } : false,
    // Compatibility mode deliberately avoids top-level and property mangling.
    // Local bindings are still shortened, but externally visible/global names remain stable.
    mangle: obfuscate ? {
      toplevel: false,
      safari10: true
    } : false,
    keep_fnames: Boolean(obfuscate),
    keep_classnames: Boolean(obfuscate),
    module,
    format: {
      comments: false,
      beautify: !minify && !obfuscate,
      keep_numbers: true
    }
  };
}

async function transform({ source, extension, minify, obfuscate }) {
  if ((extension === '.html' || extension === '.htm') && (minify || obfuscate)) {
    return minifyHtml(source, {
      collapseWhitespace: minify,
      removeComments: minify,
      removeRedundantAttributes: minify,
      removeEmptyAttributes: minify,
      minifyCSS: minify,
      minifyJS: obfuscate ? javascriptOptions({ minify, obfuscate, module: false }) : minify
    });
  }
  if (extension === '.css' && minify) {
    const result = new CleanCSS({ level: 2 }).minify(source);
    if (result.errors.length) throw new Error(result.errors.join('; '));
    return result.styles;
  }
  if (extension === '.js' || extension === '.mjs') {
    const result = await minifyJs(source, javascriptOptions({
      minify,
      obfuscate,
      module: extension === '.mjs'
    }));
    return result.code || source;
  }
  return source;
}

transform(workerData)
  .then((output) => port.postMessage({ ok: true, output }))
  .catch((error) => port.postMessage({ ok: false, error: error.message }));
