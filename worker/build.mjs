// Reproducible build of the worker bundle content (dist/):
//   worker.js   — the legatto-forms Worker (ES module, entry, hashed into the manifest)
//   tools.mjs   — server-side deploy CLI run with node inside the app image
//   bundle.json — script name, entry, hashes and compatibility date
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { build } from 'esbuild';

const SCRIPT_NAME = 'legatto-forms';
const COMPATIBILITY_DATE = '2026-11-01';
const OUT = new URL('./dist/', import.meta.url);

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const common = { bundle: true, format: 'esm', legalComments: 'inline', minify: false, sourcemap: false, logLevel: 'warning' };

await build({
  ...common,
  entryPoints: [new URL('./src/index.ts', import.meta.url).pathname],
  outfile: new URL('worker.js', OUT).pathname,
  platform: 'neutral',
  target: 'es2022',
  conditions: ['workerd', 'worker', 'browser'],
  mainFields: ['module', 'main'],
});

await build({
  ...common,
  entryPoints: [new URL('./tools/main.ts', import.meta.url).pathname],
  outfile: new URL('tools.mjs', OUT).pathname,
  platform: 'node',
  target: 'node22',
});

const sha256 = (name) => createHash('sha256').update(readFileSync(new URL(name, OUT))).digest('hex');
const bundle = {
  v: 1,
  script_name: SCRIPT_NAME,
  entry: 'worker.js',
  entry_sha256: sha256('worker.js'),
  tools: 'tools.mjs',
  tools_sha256: sha256('tools.mjs'),
  compatibility_date: COMPATIBILITY_DATE,
};
writeFileSync(new URL('bundle.json', OUT), `${JSON.stringify(bundle, null, 2)}\n`);
process.stdout.write(`${JSON.stringify({ script_name: bundle.script_name, entry_sha256: bundle.entry_sha256 })}\n`);
