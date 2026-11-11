#!/usr/bin/env node
/**
 * Copies `web/build/` into `crates/dnscraft-api/embed-web-ui/` for the
 * `web-ui` Cargo feature. Fails if the build output is missing or still the
 * placeholder HTML so release/CI never embeds an empty UI by mistake.
 *
 * Usage (from `web/`): `node scripts/sync-embed.mjs`
 * Or: `pnpm run sync-embed` after `pnpm build`.
 */

import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const webRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const buildDir = join(webRoot, 'build');
const embedDir = join(webRoot, '..', 'crates', 'dnscraft-api', 'embed-web-ui');
const PLACEHOLDER_MARKERS = [
	'Web UI placeholder',
	'copy output here for release embed',
];

function fail(message) {
	console.error(`sync-embed: ${message}`);
	process.exit(1);
}

function assertRealSpa(indexHtml) {
	for (const marker of PLACEHOLDER_MARKERS) {
		if (indexHtml.includes(marker)) {
			fail(`build/index.html still looks like the embed placeholder (${marker})`);
		}
	}
	if (!indexHtml.includes('_app') && !indexHtml.includes('sveltekit')) {
		fail('build/index.html does not look like a SvelteKit SPA (missing _app/sveltekit markers)');
	}
}

if (!existsSync(join(buildDir, 'index.html'))) {
	fail(`missing ${buildDir}/index.html — run \`pnpm build\` first`);
}

const builtIndex = readFileSync(join(buildDir, 'index.html'), 'utf8');
assertRealSpa(builtIndex);

const hashesPath = join(buildDir, 'csp-script-hashes.json');
if (!existsSync(hashesPath)) {
	fail('missing build/csp-script-hashes.json — postbuild did not run');
}

mkdirSync(dirname(embedDir), { recursive: true });
rmSync(embedDir, { recursive: true, force: true });
mkdirSync(embedDir, { recursive: true });
cpSync(buildDir, embedDir, { recursive: true });

const embedded = readFileSync(join(embedDir, 'index.html'), 'utf8');
assertRealSpa(embedded);
// Keep a sentinel the Cargo test can optionally assert against in release jobs.
writeFileSync(join(embedDir, '.embed-source'), 'web/build\n', 'utf8');

console.log(`sync-embed: copied ${buildDir} → ${embedDir}`);
