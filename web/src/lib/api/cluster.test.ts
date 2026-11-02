import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import {
	getClusterSettings,
	invokeClusterNodeRpc,
	putClusterSettings,
	type ClusterSettings,
} from './cluster';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

const settings: ClusterSettings = {
	transport: { mode: 'auto', quic_connect_timeout_ms: 2000 },
	compression: { enabled: true, level: 3 },
	reverse_rpc: { enabled: true },
	status: {
		mode: 'auto',
		active: 'h2',
		fallback_reason: 'quic_connect_timeout',
		protocol_version: 2,
	},
	restart_required: false,
};

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	endSession();
	setPrincipal({ role: 'admin', actorId: 'alice', actorType: 'user', csrfToken: 'tok-1' });
});

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('getClusterSettings', () => {
	it('loads settings including live transport status', async () => {
		fetchMock.mockResolvedValueOnce(json(200, { data: settings }));
		await expect(getClusterSettings()).resolves.toEqual(settings);
		expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/cluster/settings');
	});
});

describe('putClusterSettings', () => {
	it('PUTs a transport mode patch with CSRF', async () => {
		const next = {
			...settings,
			transport: { ...settings.transport, mode: 'h2_only' as const },
			status: { ...settings.status!, mode: 'h2_only' as const, active: 'h2' as const },
		};
		fetchMock.mockResolvedValueOnce(json(200, { data: next }));
		await expect(putClusterSettings({ transport: { mode: 'h2_only' } })).resolves.toEqual(next);
		const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
		expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/cluster/settings');
		expect(init.method).toBe('PUT');
		expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok-1');
		expect(JSON.parse(String(init.body))).toEqual({ transport: { mode: 'h2_only' } });
	});
});

describe('invokeClusterNodeRpc', () => {
	it('posts reverse RPC to a node', async () => {
		fetchMock.mockResolvedValueOnce(json(200, { data: { ok: true, uptime_s: 12 } }));
		await expect(
			invokeClusterNodeRpc('ns1', { method: 'node.status', params: {} }),
		).resolves.toEqual({ ok: true, uptime_s: 12 });
		expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/cluster/nodes/ns1/rpc');
		const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
		expect(init.method).toBe('POST');
		expect(JSON.parse(String(init.body))).toEqual({ method: 'node.status', params: {} });
	});
});
