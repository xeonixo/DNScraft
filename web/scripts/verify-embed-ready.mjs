#!/usr/bin/env node
/**
 * CI gate: after `pnpm build`, assert `web/build/` is a real SPA suitable for
 * rust-embed — not the placeholder that ships in `embed-web-ui/` for compile-
 * only `--features web-ui` checkouts.
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const webRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const buildDir = join(webRoot, 'build');
const indexPath = join(buildDir, 'index.html');
const hashesPath = join(buildDir, 'csp-script-hashes.json');

function fail(message) {
	console.error(`verify-embed-ready: ${message}`);
	process.exit(1);
}

if (!existsSync(indexPath)) {
	fail(`missing ${indexPath} — run \`pnpm build\` first`);
}
if (!existsSync(hashesPath)) {
	fail(`missing ${hashesPath}`);
}

const html = readFileSync(indexPath, 'utf8');
if (html.includes('Web UI placeholder')) {
	fail('build/index.html still contains the embed placeholder text');
}
if (!html.includes('_app') && !html.includes('sveltekit')) {
	fail('build/index.html does not look like a SvelteKit SPA');
}

const hashes = JSON.parse(readFileSync(hashesPath, 'utf8'));
if (!Array.isArray(hashes) || hashes.length === 0) {
	fail('csp-script-hashes.json must be a non-empty array');
}

console.log(`verify-embed-ready: ok (${hashes.length} CSP script hash(es))`);
