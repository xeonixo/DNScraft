import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { settle } from './result';
import {
	flushCache,
	getDomainStats,
	getReadiness,
	getTopDomains,
	periodQuery,
	pauseFilterSet,
	type Period,
} from './stats';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	endSession();
	setPrincipal({ role: 'admin', actorId: 'alice', actorType: 'user', csrfToken: 'tok-1' });
});

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('periodQuery', () => {
	const now = new Date('2026-10-28T12:00:00.000Z');

	it.each([
		['24h', 1],
		['7d', 7],
		['30d', 30],
		['1y', 365],
	] as [Period, number][])('covers %s ending now', (period, days) => {
		const params = new URLSearchParams(periodQuery(period, now));
		expect(params.get('to')).toBe('2026-10-28T12:00:00.000Z');
		const span = Date.parse(params.get('to') ?? '') - Date.parse(params.get('from') ?? '');
		expect(span).toBe(days * 86_400_000);
	});
});

describe('readiness', () => {
	it('is ready on a 200 from the root readyz path', async () => {
		fetchMock.mockResolvedValueOnce(json(200, { data: { ready: true } }));
		await expect(getReadiness()).resolves.toEqual({ ready: true, modules: [] });
		expect(fetchMock.mock.calls[0]?.[0]).toBe('/readyz');
	});

	it('reads the starting modules from a 503 not_ready answer', async () => {
		fetchMock.mockResolvedValueOnce(
			json(503, { error: { code: 'control_api.not_ready', params: { modules: ['resolver'] } } }),
		);
		await expect(getReadiness()).resolves.toEqual({ ready: false, modules: ['resolver'] });
	});
});

describe('settle', () => {
	it('maps 404 to unavailable and keeps other failures as errors', async () => {
		fetchMock.mockResolvedValueOnce(
			json(404, { error: { code: 'control_api.not_found', params: {} } }),
		);
		await expect(settle(getTopDomains('24h', 10))).resolves.toEqual({
			kind: 'unavailable',
			code: 'control_api.not_found',
		});

		fetchMock.mockResolvedValueOnce(json(500, { error: { code: 'control_api.internal' } }));
		await expect(settle(getTopDomains('24h', 10))).resolves.toEqual({
			kind: 'error',
			code: 'control_api.internal',
			params: {},
		});
	});

	it('unwraps the data of a success', async () => {
		fetchMock.mockResolvedValueOnce(json(200, { data: { domains: [] } }));
		await expect(settle(getTopDomains('7d', 5))).resolves.toEqual({ kind: 'ok', data: [] });
		expect(fetchMock.mock.calls[0]?.[0]).toMatch(/\/api\/v1\/stats\/top_domains\?from=.*&limit=5$/);
	});
});

describe('getDomainStats', () => {
	const detail = {
		domain: 'ads.example.com',
		retention_limited: true,
		first_seen: '2026-10-01T00:00:00.000000Z',
		last_seen: '2026-10-28T12:00:00.000000Z',
		counts: { total: 10, blocked: 4, allowed: 6 },
		top_clients: [{ client: 'iPhone', queries: 7 }],
		daily: [{ day: '2026-10-28', total: 10, blocked: 4 }],
		last_decision: null,
	};

	it('requests the encoded name and the day window', async () => {
		fetchMock.mockResolvedValueOnce(json(200, { data: detail }));
		await expect(getDomainStats('bücher.example', 30)).resolves.toEqual({
			...detail,
			domain: 'ads.example.com',
		});
		expect(fetchMock.mock.calls[0]?.[0]).toBe(
			`/api/v1/stats/domains/${encodeURIComponent('bücher.example')}?days=30`,
		);
	});

	it('keeps client names as text and reads a last decision', async () => {
		const client = '<script>alert(1)</script>';
		fetchMock.mockResolvedValueOnce(
			json(200, {
				data: {
					...detail,
					top_clients: [{ client, queries: 2 }],
					last_decision: {
						id: 'q-9',
						time: '2026-10-28T12:00:00.000000Z',
						status: 'blocked',
						rule_text: '||ads.example.com^',
						source: 'list',
					},
				},
			}),
		);
		const stats = await getDomainStats('ads.example.com', 7);
		expect(stats.top_clients).toEqual([{ client, queries: 2 }]);
		expect(stats.last_decision?.rule_text).toBe('||ads.example.com^');
		expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/stats/domains/ads.example.com?days=7');
	});

	it('rejects a body that is missing the domain', async () => {
		fetchMock.mockResolvedValueOnce(json(200, { data: { counts: {} } }));
		await expect(getDomainStats('ads.example.com')).rejects.toMatchObject({
			code: 'client.malformed',
		});
	});
});

describe('mutations', () => {
	it('posts the pause body to the filtering endpoint with the CSRF header', async () => {
		fetchMock.mockResolvedValueOnce(
			json(200, { data: { filter_set_id: 'default', paused_until: '2026-10-28T12:05:00Z' } }),
		);
		await pauseFilterSet('PT5M');
		const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
		expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/filtering/pause');
		expect(init.method).toBe('POST');
		expect(JSON.parse(String(init.body))).toEqual({ filter_set_id: 'default', duration: 'PT5M' });
		expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok-1');
	});

	it('sends an empty body for a whole-cache flush and the domain otherwise', async () => {
		fetchMock.mockResolvedValueOnce(
			json(200, { data: { scope: 'all', domain: null, evicted: 9 } }),
		);
		fetchMock.mockResolvedValueOnce(
			json(200, { data: { scope: 'domain', domain: 'example.com', evicted: 2 } }),
		);
		await flushCache(null);
		await flushCache('example.com');
		expect(JSON.parse(String((fetchMock.mock.calls[0]?.[1] as RequestInit).body))).toEqual({});
		expect(JSON.parse(String((fetchMock.mock.calls[1]?.[1] as RequestInit).body))).toEqual({
			domain: 'example.com',
		});
	});
});
