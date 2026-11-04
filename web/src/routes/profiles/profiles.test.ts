// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import ProfilesPage from './+page.svelte';
import ListenersPage from '../listeners/+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string): Response => json(status, { error: { code } });

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, (init?: RequestInit, url?: string) => Response>;

function profile(id: string): Record<string, unknown> {
	return {
		id,
		filter_set: 'default',
		suppress_aaaa: false,
		firefox_canary: false,
		icloud_private_relay: false,
		rebind: null,
		rebind_exceptions: [],
		forward_zones: null,
		safesearch: null,
		schedules: [],
	};
}

function serve(
	overrides: Record<string, (init?: RequestInit, url?: string) => Response> = {},
): void {
	handlers = {
		'GET /api/v1/auth/me': () =>
			ok({ role: 'admin', actor_id: 'admin', actor_type: 'user', csrf_token: 'tok' }),
		'GET /api/v1/config': () =>
			ok({
				version: 3,
				config: {
					policy: { profiles: [profile('default'), profile('kids'), profile('guest')] },
					resolver: { forward_zones: [] },
				},
			}),
		'GET /api/v1/policy/views': () =>
			ok({
				views: [
					{ id: 'lan', is_default: true, subnets: [], nodes: [], profile: 'default' },
					{ id: 'office', is_default: false, subnets: [], nodes: [], profile: 'kids' },
				],
			}),
		'GET /api/v1/filter-sets': () => ok({ filter_sets: [] }),
		'GET /api/v1/listeners': () =>
			ok({
				listeners: [
					{
						id: 'doh-main',
						protocol: 'doh',
						address: '127.0.0.1:443',
						exposure: 'local',
						h3: false,
						nodes: [],
					},
				],
			}),
		'GET /api/v1/cluster/nodes': () => ok([]),
		...overrides,
	};
	fetchMock.mockImplementation(async (input, init) => {
		const url = String(input);
		const method = init?.method ?? 'GET';
		const path = url.split('?')[0];
		const handler = handlers[`${method} ${path}`];
		return handler ? handler(init, url) : fail(404, 'control_api.not_found');
	});
}

beforeEach(() => {
	fetchMock = vi.fn();
	vi.stubGlobal('fetch', fetchMock);
	setPrincipal({ role: 'admin', actorId: 'admin', actorType: 'user', csrfToken: 'tok' });
	serve();
});

afterEach(() => {
	cleanup();
	endSession();
	vi.unstubAllGlobals();
});

describe('profiles delete guard', () => {
	it('disables delete for the default profile with the reason as tooltip', async () => {
		render(ProfilesPage);
		const deletes = await screen.findAllByRole('button', { name: m.action_delete() });
		// Rows follow config order: default, kids, guest.
		expect(deletes[0]).toBeDisabled();
		expect(deletes[0]).toHaveAttribute('title', m.profiles_delete_blocked_default());
	});

	it('disables delete for a profile still used by a Netzbereich and names the range', async () => {
		render(ProfilesPage);
		const deletes = await screen.findAllByRole('button', { name: m.action_delete() });
		expect(deletes[1]).toBeDisabled();
		expect(deletes[1]).toHaveAttribute(
			'title',
			m.profiles_delete_blocked_in_use({ zones: 'office' }),
		);
	});

	it('deletes an unused profile only after confirmation', async () => {
		handlers['DELETE /api/v1/policy/profiles/guest'] = () => ok({ version: 4 });
		const user = userEvent.setup();
		render(ProfilesPage);
		const deletes = await screen.findAllByRole('button', { name: m.action_delete() });
		expect(deletes[2]).toBeEnabled();
		await user.click(deletes[2]);
		const dialog = await screen.findByRole('dialog');
		expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false);
		await user.click(within(dialog).getByRole('button', { name: m.action_delete() }));
		await waitFor(() =>
			expect(
				fetchMock.mock.calls.some(
					([url, init]) =>
						String(url).endsWith('/policy/profiles/guest') && init?.method === 'DELETE',
				),
			).toBe(true),
		);
	});
});

describe('listeners delete confirmation', () => {
	it('names the listener and says clients using it lose DNS', async () => {
		const user = userEvent.setup();
		render(ListenersPage);
		const deletes = await screen.findAllByRole('button', { name: m.action_delete() });
		await user.click(deletes[0]);
		const dialog = await screen.findByRole('dialog');
		expect(
			within(dialog).getByText(
				m.listeners_delete_body_dns({ id: 'doh-main', address: '127.0.0.1:443' }),
			),
		).toBeInTheDocument();
	});
});
