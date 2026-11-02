// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Page from './+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});

afterEach(() => {
	cleanup();
	endSession();
	vi.unstubAllGlobals();
});

beforeEach(() => {
	setPrincipal({ role: 'admin', actorId: 'admin', actorType: 'user', csrfToken: 'tok' });
	vi.stubGlobal(
		'fetch',
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			if (url.includes('/api/v1/auth/me')) {
				return json(200, {
					data: { role: 'admin', actor_id: 'admin', actor_type: 'user', csrf_token: 'tok' },
				});
			}
			if (url.includes('/api/v1/config') && (init?.method ?? 'GET') === 'GET') {
				return json(200, {
					data: {
						version: 2,
						config: {
							resolver: {
								cache_size_mb: 64,
								query_timeout: '1500ms',
								forward_zones: [{ id: 'lab', zone: 'lab.test', targets: [], validate: false }],
							},
						},
					},
				});
			}
			return json(404, { error: { code: 'control_api.not_found' } });
		}),
	);
});

describe('/resolver', () => {
	it('loads resolver fields and shows save for admins', async () => {
		render(Page);
		await waitFor(() => {
			expect(screen.getByRole('button', { name: m.action_save() })).toBeInTheDocument();
		});
		const cache = document.getElementById('res-cache-mb') as HTMLInputElement;
		expect(cache.value).toBe('64');
	});
});
