import { describe, expect, it } from 'vitest';
import type { DecisionStep, QueryRecord } from '$lib/api/query-log';
import { m } from '$lib/paraglide/messages';
import {
	collapseBursts,
	dnssecLabel,
	statusOf,
	stageLabel,
	stepDetail,
	trackerCategoryLabel,
	trackerForName,
	trackerKind,
	trackersOf,
	verdictLabel,
	verdictStyle,
} from './view';

const base = { filter: null, rcode: 'NOERROR', dnssec: 'secure' } as const;

describe('statusOf', () => {
	it('derives the outcome the way the server does', () => {
		expect(statusOf(base)).toBe('allowed');
		expect(
			statusOf({
				...base,
				filter: {
					reason: 'list',
					block_mode: 'nxdomain',
					rule_text: '||ads^',
					list_id: 'l',
					important: false,
				},
			}),
		).toBe('blocked');
		expect(statusOf({ ...base, rcode: 'SERVFAIL' })).toBe('servfail');
		expect(statusOf({ ...base, dnssec: 'bogus' })).toBe('dnssec_bogus');
	});

	it('does not call a filter hit without a block mode blocked', () => {
		const hit = {
			reason: 'temporary_allow',
			block_mode: null,
			rule_text: null,
			list_id: null,
			important: false,
		};
		expect(statusOf({ ...base, filter: hit })).toBe('allowed');
	});
});

describe('labels', () => {
	it('translates known stages and verdicts and keeps unknown identifiers', () => {
		expect(stageLabel('filter_qname')).toBe(m.querylog_stage_filter_qname());
		expect(stageLabel('future_stage')).toBe('future_stage');
		expect(verdictLabel('nxdomain')).toBe(m.querylog_verdict_nxdomain());
		expect(verdictLabel('future_verdict')).toBe('future_verdict');
	});

	it('pairs blocking verdicts with the danger tone and an icon', () => {
		expect(verdictStyle('blocked')).toEqual({ tone: 'danger', icon: 'ban' });
		expect(verdictStyle('answered')).toEqual({ tone: 'ok', icon: 'check-circle' });
	});

	it('reports a missing DNSSEC status as not checked', () => {
		expect(dnssecLabel(null)).toBe(m.querylog_not_checked());
		expect(dnssecLabel('bogus')).toBe(m.querylog_dnssec_bogus());
	});
});

describe('stepDetail', () => {
	const step = (value: Partial<DecisionStep>): DecisionStep =>
		({ stage: 'x', verdict: 'y', ...value }) as DecisionStep;

	it('shows the source of a resolution and the cause of a failed one', () => {
		expect(stepDetail(step({ stage: 'resolve', verdict: 'resolved', source: 'cache' }))).toEqual({
			text: m.querylog_step_from({ source: 'Cache' }),
			mono: false,
		});
		expect(
			stepDetail(step({ stage: 'resolve', verdict: 'failed', cause_code: 'timeout' })),
		).toEqual({ text: m.querylog_step_error({ code: 'timeout' }), mono: true });
	});

	it('returns nothing for a step without a useful value', () => {
		expect(stepDetail(step({ stage: 'bypass', verdict: 'answered' }))).toBeNull();
	});
});

describe('record shape used in tests', () => {
	it('accepts the documented base fields', () => {
		const record: Pick<QueryRecord, 'filter' | 'rcode' | 'dnssec'> = base;
		expect(record.rcode).toBe('NOERROR');
	});
});

describe('trackerCategoryLabel', () => {
	it('translates known categories and echoes unknown ones', () => {
		expect(trackerCategoryLabel('advertising')).toBe(m.tracker_category_advertising());
		expect(trackerCategoryLabel('brand_new')).toBe('brand_new');
		expect(trackerCategoryLabel('constructor')).toBe('constructor');
	});
});

describe('trackerKind', () => {
	it('separates tracking from functional categories', () => {
		expect(trackerKind('advertising')).toBe('tracking');
		expect(trackerKind('site_analytics')).toBe('tracking');
		expect(trackerKind('cdn')).toBe('functional');
		expect(trackerKind('hosting')).toBe('functional');
		expect(trackerKind('misc')).toBe('unclear');
		expect(trackerKind('brand_new')).toBe('unclear');
	});
});

describe('trackerForName', () => {
	const record = {
		query: { name: 'a.example', type: 'A', class: 'IN' },
		tracker: { name: 'Own', category: 'cdn' },
		steps: [
			{
				stage: 'cname_chain',
				verdict: 'resolved',
				hops: [
					{ name: 'a.example', verdict: 'pass' },
					{
						name: 'b.example',
						verdict: 'blocked',
						tracker: { name: 'Hop', category: 'advertising' },
					},
				],
			},
		],
	} as unknown as QueryRecord;

	it('finds the queried name and a CNAME hop, and nothing else', () => {
		expect(trackerForName(record, 'a.example')?.name).toBe('Own');
		expect(trackerForName(record, 'b.example')?.name).toBe('Hop');
		expect(trackerForName(record, 'c.example')).toBeNull();
	});
});

describe('trackersOf', () => {
	it('returns only the queried-name label when there is no chain', () => {
		const record = {
			query: { name: 'ads.example', type: 'A', class: 'IN' },
			tracker: { name: 'Ads', category: 'advertising' },
			steps: [],
		} as unknown as QueryRecord;
		expect(trackersOf(record).map((t) => t.name)).toEqual(['Ads']);
	});

	it('surfaces a hop label when the queried name is unlabeled (CDN chain)', () => {
		const record = {
			query: { name: 'downloads.cursor.com', type: 'AAAA', class: 'IN' },
			steps: [
				{
					stage: 'cname_chain',
					verdict: 'resolved',
					hops: [
						{ name: 'downloads.cursor.com', verdict: 'pass' },
						{
							name: 'downloads.cursor.com.cdn.cloudflare.net',
							verdict: 'pass',
							tracker: { name: 'CloudFlare', category: 'cdn' },
						},
					],
				},
			],
		} as unknown as QueryRecord;
		expect(trackersOf(record)).toEqual([{ name: 'CloudFlare', category: 'cdn' }]);
	});

	it('dedupes when the first hop repeats the queried-name tracker', () => {
		const record = {
			query: { name: 'a.example', type: 'A', class: 'IN' },
			tracker: { name: 'Own', category: 'cdn' },
			steps: [
				{
					stage: 'cname_chain',
					verdict: 'resolved',
					hops: [
						{
							name: 'a.example',
							verdict: 'pass',
							tracker: { name: 'Own', category: 'cdn' },
						},
						{
							name: 'b.example',
							verdict: 'pass',
							tracker: { name: 'Hop', category: 'advertising' },
						},
					],
				},
			],
		} as unknown as QueryRecord;
		expect(trackersOf(record).map((t) => t.name)).toEqual(['Hop', 'Own']);
	});

	it('orders tracking before functional before unclear', () => {
		const record = {
			query: { name: 'a.example', type: 'A', class: 'IN' },
			tracker: { name: 'Misc', category: 'misc' },
			steps: [
				{
					stage: 'cname_chain',
					verdict: 'resolved',
					hops: [
						{ name: 'a.example', verdict: 'pass' },
						{
							name: 'cdn.example',
							verdict: 'pass',
							tracker: { name: 'CDN', category: 'cdn' },
						},
						{
							name: 'ads.example',
							verdict: 'pass',
							tracker: { name: 'Ads', category: 'advertising' },
						},
					],
				},
			],
		} as unknown as QueryRecord;
		expect(trackersOf(record).map((t) => t.name)).toEqual(['Ads', 'CDN', 'Misc']);
	});
});

describe('collapseBursts', () => {
	const row = (id: string, time: string, type: string, over: Partial<QueryRecord> = {}) =>
		({
			id,
			time,
			query: { name: 'owa.example', type, class: 'IN' },
			source_ip: '10.0.0.1',
			client_id: null,
			device_id: null,
			protocol: 'udp53',
			node_id: 'n1',
			rcode: 'NOERROR',
			dnssec: null,
			filter: null,
			timings: { total_us: 1000 },
			...over,
		}) as unknown as QueryRecord;

	it('folds A/AAAA/HTTPS of one lookup into the newest row and keeps the slowest time', () => {
		const { rows, bursts } = collapseBursts([
			row('a', '2026-11-04T08:52:06.900Z', 'A'),
			row('b', '2026-11-04T08:52:06.500Z', 'AAAA', { timings: { total_us: 4_000_000 } } as never),
			row('c', '2026-11-04T08:52:06.100Z', 'A'),
			row('d', '2026-11-04T08:52:05.900Z', 'HTTPS'),
		]);
		expect(rows.map((r) => r.id)).toEqual(['a']);
		expect(bursts.get('a')).toEqual({
			count: 4,
			types: ['A', 'AAAA', 'HTTPS'],
			worstUs: 4_000_000,
		});
	});

	it('keeps rows apart when the client, outcome or gap differ', () => {
		const { rows, bursts } = collapseBursts([
			row('a', '2026-11-04T08:52:10Z', 'A'),
			row('b', '2026-11-04T08:52:09Z', 'A', { source_ip: '10.0.0.2' }),
			row('c', '2026-11-04T08:52:08Z', 'A', { rcode: 'SERVFAIL' }),
			row('d', '2026-11-04T08:52:01Z', 'A', { rcode: 'SERVFAIL' }),
		]);
		expect(rows.map((r) => r.id)).toEqual(['a', 'b', 'c', 'd']);
		expect(bursts.size).toBe(0);
	});
});
