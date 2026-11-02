// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';
import Page from './+page.svelte';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });

afterEach(() => {
	cleanup();
	endSession();
	vi.unstubAllGlobals();
});

beforeEach(() => {
	setPrincipal({
		role: 'admin',
		actorId: 'ops',
		csrfToken: 'csrf',
		actorType: 'local',
	});
});

function mockApi(alerts: unknown, notifications?: unknown): void {
	vi.stubGlobal(
		'fetch',
		vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.includes('/api/v1/alerts')) return ok(alerts);
			if (url.includes('/api/v1/notifications')) {
				return ok(
					notifications ?? {
						channels: [],
						allowed_hosts: [],
						allow_private_destinations: false,
						event_catalog: ['tls.cert.expiring'],
					},
				);
			}
			if (url.includes('/api/v1/config')) return ok({ version: 1, config: {} });
			return json(404, { error: { code: 'control_api.not_found' } });
		}),
	);
}

describe('/alerts', () => {
	it('shows the empty state when there are no alerts', async () => {
		mockApi({ active_count: 0, items: [] });
		render(Page);
		await waitFor(() => {
			expect(screen.getByText(m.alerts_empty_title())).toBeInTheDocument();
		});
	});

	it('lists active alerts by module', async () => {
		mockApi({
			active_count: 1,
			items: [
				{
					id: 'tls.cert.expiring',
					severity: 'warning',
					module: 'tls',
					params: { days_to_expiry: 5 },
					target_route: '/tls',
				},
			],
		});
		render(Page);
		await waitFor(() => {
			expect(screen.getByText(m.alert_tls_cert_expiring({ days: '5' }))).toBeInTheDocument();
		});
		expect(screen.getByText(m.alert_module_tls())).toBeInTheDocument();
	});

	it('never shows a secret value in the channels section', async () => {
		mockApi(
			{ active_count: 0, items: [] },
			{
				channels: [
					{
						id: 'ops',
						type: 'webhook',
						enabled: true,
						host: 'hooks.example.com',
						has_secret: true,
						events: ['tls.cert.expiring'],
					},
				],
				allowed_hosts: ['hooks.example.com'],
				allow_private_destinations: false,
				event_catalog: ['tls.cert.expiring'],
			},
		);
		const user = (await import('@testing-library/user-event')).default.setup();
		render(Page);
		await waitFor(() => {
			expect(screen.getByText('ops')).toBeInTheDocument();
		});
		await user.click(screen.getByRole('button', { name: m.alerts_channels_edit() }));
		await waitFor(() => {
			expect(screen.getByLabelText(m.alerts_channels_secret())).toBeInTheDocument();
		});
		const secret = screen.getByLabelText(m.alerts_channels_secret()) as HTMLInputElement;
		expect(secret.value).toBe('');
		expect(secret.placeholder).toBe(m.alerts_channels_secret_set());
		expect(document.body.textContent ?? '').not.toMatch(/super-secret/);
	});
});
