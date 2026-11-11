import { describe, expect, it } from 'vitest';
import {
	FEEDBACK_SCHEMA_VERSION,
	buildDiagnostics,
	buildMarkdown,
} from './feedback';

describe('feedback markdown', () => {
	it('uses fixed English headings and a JSON diagnostics fence', () => {
		const diagnostics = buildDiagnostics({
			locale: 'de',
			route: '/feedback',
			dnscraftVersion: '0.3.12',
			nodeRole: 'standalone',
			errorCodes: ['control_api.auth.locked'],
		});
		expect(diagnostics.schema_version).toBe(FEEDBACK_SCHEMA_VERSION);
		expect(diagnostics.recent_log_lines).toEqual([]);

		const md = buildMarkdown({
			summary: 'Pause stuck',
			expected: 'Resume within a second',
			actual: 'Spinner forever',
			diagnostics,
		});
		expect(md).toContain('## Summary');
		expect(md).toContain('## Expected');
		expect(md).toContain('## Actual');
		expect(md).toContain('## Diagnostics');
		expect(md).toContain('```json');
		expect(md).toContain('"dnscraft_version": "0.3.12"');
		expect(md).toContain('control_api.auth.locked');
		expect(md).not.toContain('Zusammenfassung');
	});
});
