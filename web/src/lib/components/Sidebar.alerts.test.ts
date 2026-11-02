// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, waitFor } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import Sidebar from './Sidebar.svelte';

const json = (body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status: 200,
		headers: { 'Content-Type': 'application/json' },
	});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function mockApis(activeCount: number): void {
	vi.stubGlobal(
		'fetch',
		vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.includes('/api/v1/status')) {
				return json({ data: { version: '1.0.0', ready: true, modules_not_ready: [] } });
			}
			if (url.includes('/api/v1/alerts')) {
				return json({ data: { active_count: activeCount, items: [] } });
			}
			return new Response(JSON.stringify({ error: { code: 'control_api.not_found' } }), {
				status: 404,
			});
		}),
	);
}

describe('Sidebar alert badge', () => {
	it('shows the active alert count on the alerts nav item', async () => {
		mockApis(3);
		const { container } = render(Sidebar, { props: { currentPath: '/dashboard' } });
		await waitFor(() => {
			expect(container.querySelector('.nav-badge')?.textContent).toBe('3');
		});
	});

	it('hides the badge when there are no alerts', async () => {
		mockApis(0);
		const { container } = render(Sidebar, { props: { currentPath: '/dashboard' } });
		await waitFor(() => {
			expect(vi.mocked(fetch)).toHaveBeenCalled();
		});
		expect(container.querySelector('.nav-badge')).toBeNull();
	});
});
