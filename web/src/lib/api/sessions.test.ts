import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { listSessions, revokeSession } from './sessions';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

const row = {
	id: 'abc/def',
	actor_id: 'alice',
	actor_type: 'user',
	role: 'admin',
	client_label: 'Firefox on macOS',
	ip: '192.0.2.0',
	created_at: '2026-10-01T00:00:00Z',
	last_seen: '2026-10-28T12:00:00Z',
	expires_at: '2026-11-01T00:00:00Z',
	current: true,
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

describe('listSessions', () => {
	it('requests scope and offset and keeps nullable fields', async () => {
		fetchMock.mockResolvedValueOnce(
			json(200, {
				data: {
					items: [{ ...row, client_label: null, ip: null, current: false }],
					has_more: true,
					next_offset: 50,
				},
			}),
		);
		await expect(listSessions('all', 50)).resolves.toEqual({
			items: [{ ...row, client_label: null, ip: null, current: false }],
			has_more: true,
			next_offset: 50,
		});
		const url = new URL(String(fetchMock.mock.calls[0]?.[0]), 'http://localhost');
		expect(url.pathname).toBe('/api/v1/auth/sessions');
		expect(url.searchParams.get('scope')).toBe('all');
		expect(url.searchParams.get('offset')).toBe('50');
	});

	it('rejects a body without items', async () => {
		fetchMock.mockResolvedValueOnce(json(200, { data: {} }));
		await expect(listSessions('own')).rejects.toMatchObject({ code: 'client.malformed' });
	});
});

describe('revokeSession', () => {
	it('deletes the encoded id with the CSRF header', async () => {
		fetchMock.mockResolvedValueOnce(json(200, { data: { id: row.id, revoked: true } }));
		await expect(revokeSession(row.id)).resolves.toEqual({ id: row.id, revoked: true });
		const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
		expect(fetchMock.mock.calls[0]?.[0]).toBe(
			`/api/v1/auth/sessions/${encodeURIComponent(row.id)}`,
		);
		expect(init.method).toBe('DELETE');
		expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok-1');
	});
});
