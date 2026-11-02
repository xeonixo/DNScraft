// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { m } from '$lib/paraglide/messages';
import type { DomainStats } from '$lib/api/stats';
import Page from './+page.svelte';

const pageState = vi.hoisted(() => ({
	params: { name: 'ads.example.com' } as Record<string, string>,
}));
vi.mock('$app/state', () => ({
	page: {
		get url() {
			return new URL('http://localhost/dashboard/domains/ads.example.com');
		},
		get params() {
			return pageState.params;
		},
	},
}));

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string): Response => json(status, { error: { code } });

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

function detail(overrides: Partial<DomainStats> = {}): DomainStats {
	return {
		domain: 'ads.example.com',
		retention_limited: true,
		first_seen: '2026-10-01T00:00:00.000000Z',
		last_seen: '2026-10-28T12:00:00.000000Z',
		counts: { total: 10, blocked: 4, allowed: 6 },
		top_clients: [{ client: 'iPhone', queries: 7 }],
		daily: [{ day: '2026-11-01', total: 10, blocked: 4 }],
		last_decision: {
			id: 'q-9',
			time: '2026-10-28T12:00:00.000000Z',
			status: 'blocked',
			rule_text: '||ads.example.com^',
			source: 'list',
		},
		...overrides,
	};
}

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	pageState.params = { name: 'ads.example.com' };
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function serve(data: DomainStats | null, status = 200): void {
	fetchMock.mockImplementation(async () =>
		data === null ? fail(status, 'control_api.not_found') : ok(data),
	);
}

describe('domain detail', () => {
	it('domain_detail_renders_client_names_as_text', async () => {
		const script = '<script>alert(1)</script>';
		const image = '"><img src=x onerror=alert(1)>';
		serve(
			detail({
				top_clients: [
					{ client: script, queries: 3 },
					{ client: image, queries: 1 },
				],
			}),
		);
		const { container } = render(Page);

		expect(await screen.findByText(script)).toBeInTheDocument();
		expect(screen.getByText(image)).toBeInTheDocument();
		expect(screen.getByText(script).closest('a')).toBeNull();
		expect(container.querySelector('script')).toBeNull();
		expect(container.querySelector('img')).toBeNull();
		expect(screen.getByText(m.domain_detail_retention())).toBeInTheDocument();
		expect(screen.getByText('||ads.example.com^')).toBeInTheDocument();
		expect(container.querySelector('a[href="/query-log/q-9"]')).not.toBeNull();
		expect(String(fetchMock.mock.calls[0]?.[0])).toContain('days=7');
	});

	it('switches between 7 and 30 days', async () => {
		serve(detail());
		const user = userEvent.setup();
		render(Page);

		await screen.findByText('iPhone');
		await user.click(screen.getByRole('radio', { name: m.domain_detail_days_30() }));
		await waitFor(() => {
			const urls = fetchMock.mock.calls.map(([input]) => String(input));
			expect(urls.some((url) => url.includes('days=30'))).toBe(true);
		});
	});

	it('shows an empty state when the domain was not seen', async () => {
		serve(null, 404);
		render(Page);

		expect(await screen.findByText(m.domain_detail_unseen())).toBeInTheDocument();
		expect(screen.getByText(m.domain_detail_unseen_body())).toBeInTheDocument();
		expect(screen.queryByRole('alert')).toBeNull();
	});

	it('shows the daily breakdown', async () => {
		serve(detail());
		render(Page);

		expect(
			await screen.findByText(m.domain_detail_daily_blocked({ count: '4' })),
		).toBeInTheDocument();
		expect(screen.getByText(m.domain_detail_daily())).toBeInTheDocument();
	});
});
