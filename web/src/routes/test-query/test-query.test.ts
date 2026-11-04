// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import TestQueryPage from './+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>(
		async () =>
			new Response(
				JSON.stringify({
					data: { steps: [], answer: { rcode: 'NOERROR', records: [] } },
				}),
				{ status: 200, headers: { 'Content-Type': 'application/json' } },
			),
	);
	vi.stubGlobal('fetch', fetchMock);
	setPrincipal({ role: 'admin', actorId: 'admin', actorType: 'user', csrfToken: 'tok' });
});

afterEach(() => {
	cleanup();
	endSession();
	vi.unstubAllGlobals();
});

describe('Test-Abfrage query type', () => {
	it('offers the API record types and sends the picked one', async () => {
		const user = userEvent.setup();
		render(TestQueryPage);
		for (const label of ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV']) {
			expect(screen.getByRole('radio', { name: label })).toBeInTheDocument();
		}

		await user.click(screen.getByRole('radio', { name: 'TXT' }));
		await user.click(screen.getByRole('button', { name: m.test_query_run() }));

		const post = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST');
		expect(JSON.parse(String(post?.[1]?.body))).toMatchObject({ qtype: 'TXT' });
	});
});
