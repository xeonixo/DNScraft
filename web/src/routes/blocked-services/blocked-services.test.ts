// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import BlockedServicesPage from './+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { formatDateTime } from '$lib/format';
import { getLocale } from '$lib/i18n/locale';
import { m } from '$lib/paraglide/messages';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });

type Handler = (init?: RequestInit) => Response;

const UPDATED = '2026-10-28T12:00:00Z';

const CATALOG = {
	available: true,
	catalog_updated_at: UPDATED,
	locale: 'en',
	items: [
		{
			id: 'youtube',
			name: 'YouTube',
			group: 'Video',
			group_id: 'video',
			icon_svg: '<svg><script>alert(1)</script></svg>',
			enabled: { default: true, kids: false },
		},
		{
			id: 'tiktok',
			name: 'TikTok',
			group: 'Social',
			group_id: 'social',
			enabled: { default: false, kids: true },
		},
		{
			id: 'netflix',
			name: 'Netflix',
			group: 'Video',
			group_id: 'video',
			enabled: { default: false, kids: false },
		},
	],
};

const SETS = [
	{
		id: 'default',
		name: 'Default',
		lists: [],
		custom_rules: '',
		services: ['youtube'],
		block_mode: 'refused',
	},
	{
		id: 'kids',
		name: 'Kids',
		lists: [],
		custom_rules: '',
		services: ['tiktok'],
		block_mode: 'refused',
	},
];

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, Handler>;

function serve(overrides: Record<string, Handler> = {}): void {
	handlers = {
		'GET /api/v1/filtering/services': () => ok(CATALOG),
		'GET /api/v1/filter-sets': () => ok({ filter_sets: SETS }),
		'PUT /api/v1/filtering/services/youtube': () =>
			ok({ version: 4, service_id: 'youtube', filter_set_id: 'kids', enabled: true }),
		...overrides,
	};
	fetchMock.mockImplementation(async (input, init) => {
		const url = String(input);
		const handler = handlers[`${init?.method ?? 'GET'} ${url.split('?')[0]}`];
		return handler ? handler(init) : json(404, { error: { code: 'control_api.not_found' } });
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

const bodyOf = (method: string): Record<string, unknown> | undefined => {
	const call = fetchMock.mock.calls.find(([, init]) => init?.method === method);
	return call ? JSON.parse(String(call[1]?.body)) : undefined;
};

const toggleName = (service: string, set: string): string =>
	m.blocked_services_toggle({ service, set });

describe('blocked-services page', () => {
	it('groups the catalog and labels a switch for each filter set', async () => {
		render(BlockedServicesPage);
		expect(await screen.findByText(m.blocked_services_lead())).toBeInTheDocument();
		expect(
			await screen.findByText(
				m.blocked_services_updated({
					when: formatDateTime(new Date(UPDATED), getLocale()),
				}),
			),
		).toBeInTheDocument();

		const video = screen.getByRole('region', { name: 'Video' });
		expect(within(video).getByText('YouTube')).toBeInTheDocument();
		expect(within(video).getByText('Netflix')).toBeInTheDocument();
		expect(within(video).queryByText('TikTok')).toBeNull();
		expect(screen.getByRole('region', { name: 'Social' })).toBeInTheDocument();

		expect(screen.getByRole('switch', { name: toggleName('YouTube', 'Default') })).toBeChecked();
		expect(screen.getByRole('switch', { name: toggleName('YouTube', 'Kids') })).not.toBeChecked();
		expect(screen.getByRole('switch', { name: toggleName('TikTok', 'Kids') })).toBeChecked();
		expect(document.querySelector('img, svg')).toBeNull();

		const servicesCall = fetchMock.mock.calls.find(([url]) =>
			String(url).includes('/filtering/services'),
		);
		expect(String(servicesCall?.[0])).toContain(`locale=${encodeURIComponent(getLocale())}`);
	});

	it('saves a per-set toggle for an admin', async () => {
		const user = userEvent.setup();
		render(BlockedServicesPage);
		const sw = await screen.findByRole('switch', { name: toggleName('YouTube', 'Kids') });
		sw.focus();
		await user.keyboard(' ');
		await waitFor(() => expect(bodyOf('PUT')).toEqual({ filter_set_id: 'kids', enabled: true }));
		expect(sw).toBeChecked();
		const putCall = fetchMock.mock.calls.find(([, init]) => init?.method === 'PUT');
		expect(String(putCall?.[0])).toBe('/api/v1/filtering/services/youtube');
	});

	it('puts the switch back when the save fails', async () => {
		serve({
			'PUT /api/v1/filtering/services/youtube': () =>
				json(400, { error: { code: 'filtering.service.unknown' } }),
		});
		const user = userEvent.setup();
		render(BlockedServicesPage);
		const sw = await screen.findByRole('switch', { name: toggleName('YouTube', 'Kids') });
		sw.focus();
		await user.keyboard(' ');
		expect(await screen.findByRole('alert')).toHaveTextContent(m.error_filtering_service_unknown());
		await waitFor(() => expect(sw).not.toBeChecked());
	});

	it('keeps the switches read-only for a viewer', async () => {
		setPrincipal({ role: 'viewer', actorId: 'bob', actorType: 'user', csrfToken: null });
		const user = userEvent.setup();
		render(BlockedServicesPage);
		const sw = await screen.findByRole('switch', { name: toggleName('YouTube', 'Kids') });
		expect(sw).toBeDisabled();
		expect(sw).not.toBeChecked();
		sw.focus();
		await user.keyboard(' ');
		expect(bodyOf('PUT')).toBeUndefined();
		expect(sw).not.toBeChecked();
	});

	it('shows the unavailable state when the catalog is not loaded', async () => {
		serve({
			'GET /api/v1/filtering/services': () =>
				ok({
					available: false,
					catalog_updated_at: null,
					locale: 'en',
					items: [],
				}),
		});
		render(BlockedServicesPage);
		expect(await screen.findByText(m.dashboard_unavailable_title())).toBeInTheDocument();
		expect(screen.queryByText('YouTube')).toBeNull();
		expect(screen.queryByRole('switch')).toBeNull();
		expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/filter-sets'))).toBe(false);
	});

	it('shows the unavailable state when the catalog endpoint is missing', async () => {
		serve({
			'GET /api/v1/filtering/services': () =>
				json(404, { error: { code: 'control_api.not_found' } }),
		});
		render(BlockedServicesPage);
		expect(await screen.findByText(m.dashboard_unavailable_title())).toBeInTheDocument();
		expect(screen.queryByRole('switch')).toBeNull();
	});

	it('filters services by name and keeps only the matching categories', async () => {
		const user = userEvent.setup();
		render(BlockedServicesPage);
		await screen.findByRole('region', { name: 'Video' });
		const search = screen.getByRole('searchbox', { name: m.blocked_services_search() });

		await user.type(search, 'NETF');
		expect(screen.getByText('Netflix')).toBeInTheDocument();
		expect(screen.queryByText('YouTube')).toBeNull();
		expect(screen.queryByRole('region', { name: 'Social' })).toBeNull();

		await user.clear(search);
		await user.type(search, 'zzz');
		expect(screen.getByText(m.blocked_services_search_empty())).toBeInTheDocument();
		expect(screen.queryByRole('switch')).toBeNull();

		await user.clear(search);
		expect(screen.getByRole('region', { name: 'Social' })).toBeInTheDocument();
	});

	it('explains an empty catalog', async () => {
		serve({
			'GET /api/v1/filtering/services': () =>
				ok({ available: true, catalog_updated_at: null, locale: 'en', items: [] }),
		});
		render(BlockedServicesPage);
		expect(await screen.findByText(m.blocked_services_empty())).toBeInTheDocument();
	});

	it('lists services without switches when there is no filter set', async () => {
		serve({ 'GET /api/v1/filter-sets': () => ok({ filter_sets: [] }) });
		render(BlockedServicesPage);
		expect(await screen.findByText(m.blocked_services_no_sets())).toBeInTheDocument();
		expect(screen.getByText('YouTube')).toBeInTheDocument();
		expect(screen.queryByRole('switch')).toBeNull();
	});

	it('shows an error and loads the catalog on retry', async () => {
		serve({
			'GET /api/v1/filtering/services': () =>
				json(500, { error: { code: 'control_api.internal' } }),
		});
		const user = userEvent.setup();
		render(BlockedServicesPage);
		expect(await screen.findByRole('alert')).toHaveTextContent(m.error_control_api_internal());
		handlers['GET /api/v1/filtering/services'] = () => ok(CATALOG);
		await user.click(screen.getByRole('button', { name: m.action_retry() }));
		expect(await screen.findByRole('heading', { name: 'Video' })).toBeInTheDocument();
	});

	it('truncates a hostile service name instead of rendering it whole', async () => {
		const longName = 'x'.repeat(150);
		serve({
			'GET /api/v1/filtering/services': () =>
				ok({
					available: true,
					catalog_updated_at: null,
					locale: 'en',
					items: [
						{
							id: 'long',
							name: longName,
							group: 'Video',
							group_id: 'video',
							enabled: { default: false },
						},
					],
				}),
		});
		render(BlockedServicesPage);
		expect(await screen.findByText(/x{100,}…$/)).toBeInTheDocument();
		expect(screen.queryByText(longName)).toBeNull();
	});
});
