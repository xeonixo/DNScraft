import { describe, expect, it } from 'vitest';
import { cnameChainPreview, resolveAnswersForRecord } from './resolve-answers';
import type { PolicyRecord } from '$lib/api/policy';

const base = (
	partial: Partial<PolicyRecord> & Pick<PolicyRecord, 'name' | 'type' | 'rdata'>,
): PolicyRecord => ({
	ttl: 60,
	overrides: {},
	...partial,
});

describe('resolve-answers', () => {
	it('marks deviant views', () => {
		const record = base({
			name: 'app.example.com.',
			type: 'CNAME',
			rdata: 'cdn.example.net.',
			overrides: {
				lan: { mode: 'addresses', a: ['10.0.0.5'] },
				guests: '@public',
			},
		});
		const answers = resolveAnswersForRecord(record, ['lan', 'guests', 'iot']);
		expect(answers.find((a) => a.view === 'lan')?.mode).toBe('addresses');
		expect(answers.find((a) => a.view === 'guests')?.mode).toBe('public');
		expect(answers.find((a) => a.view === 'iot')?.deviant).toBe(false);
	});

	it('walks a local cname chain into addresses', () => {
		const records = [
			base({
				name: 'alias.example.com.',
				type: 'CNAME',
				rdata: 'mid.example.com.',
			}),
			base({
				name: 'mid.example.com.',
				type: 'CNAME',
				rdata: 'cdn.example.net.',
				overrides: { lan: { mode: 'addresses', a: ['10.0.0.9'] } },
			}),
		];
		const chain = cnameChainPreview('alias.example.com.', 'lan', records);
		expect(chain.join(' → ')).toContain('10.0.0.9');
	});
});
