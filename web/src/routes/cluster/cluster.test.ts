// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import LiveRegion from '$lib/components/LiveRegion.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { live } from '$lib/live.svelte';
import { m } from '$lib/paraglide/messages';
import Page from './+page.svelte';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });

const nodes = [
	{
		node_id: 'master',
		role: 'master',
		fingerprint: 'aa'.repeat(32),
		joined_at: '2026-01-01T00:00:00Z',
		last_seen: '2026-11-02T12:00:00Z',
		applied_config_version: 3,
		revoked: false,
		local: true,
		connected: true,
	},
	{
		node_id: 'dns1',
		display_name: 'elmo',
		role: 'sub_node',
		fingerprint: 'bb'.repeat(32),
		joined_at: '2026-01-02T00:00:00Z',
		last_seen: '2026-11-02T12:00:00Z',
		applied_config_version: 3,
		revoked: false,
		local: false,
		connected: true,
	},
];

const baseSettings = {
	transport: { mode: 'auto', quic_connect_timeout_ms: 2000 },
	compression: { enabled: true, level: 3 },
	reverse_rpc: { enabled: true },
	status: {
		mode: 'auto',
		active: 'h2',
		fallback_reason: 'quic_unavailable',
		protocol_version: 2,
	},
	restart_required: false,
};

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let settingsBody: typeof baseSettings;

beforeEach(() => {
	settingsBody = structuredClone(baseSettings);
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	endSession();
	live.message = '';
	setPrincipal({ role: 'admin', actorId: 'alice', actorType: 'user', csrfToken: 'tok' });
	fetchMock.mockImplementation(async (input, init) => {
		const url = String(input);
		const method = (init?.method ?? 'GET').toUpperCase();
		if (method === 'GET' && url.includes('/api/v1/cluster/nodes')) {
			return ok(nodes);
		}
		if (method === 'GET' && url.includes('/api/v1/cluster/settings')) {
			return ok(settingsBody);
		}
		if (method === 'PUT' && url.includes('/api/v1/cluster/settings')) {
			const patch = JSON.parse(String(init?.body ?? '{}')) as {
				transport?: { mode?: string };
			};
			if (patch.transport?.mode) {
				settingsBody = {
					...settingsBody,
					transport: {
						...settingsBody.transport,
						mode: patch.transport.mode as typeof settingsBody.transport.mode,
					},
					status: {
						...settingsBody.status,
						mode: patch.transport.mode as typeof settingsBody.status.mode,
					},
				};
			}
			return ok(settingsBody);
		}
		return json(404, { error: { code: 'control_api.not_found' } });
	});
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function renderPage(): void {
	render(LiveRegion);
	render(Page);
}

describe('cluster settings UI', () => {
	it('shows live transport and saves a mode change', async () => {
		const user = userEvent.setup();
		renderPage();

		expect(await screen.findByText(m.cluster_settings_transport_group())).toBeInTheDocument();
		expect(
			screen.getByText(m.cluster_settings_transport_live({ transport: 'HTTP/2' })),
		).toBeInTheDocument();
		expect(
			screen.getByText(m.cluster_settings_transport_fallback({ reason: 'quic_unavailable' })),
		).toBeInTheDocument();

		const segmented = screen.getByRole('radiogroup', {
			name: m.cluster_settings_transport_mode(),
		});
		await user.click(
			within(segmented).getByRole('radio', { name: m.cluster_settings_transport_h2_only() }),
		);

		await waitFor(() => {
			const put = fetchMock.mock.calls.find(
				([url, init]) =>
					String(url).includes('/api/v1/cluster/settings') &&
					(init?.method ?? '').toUpperCase() === 'PUT',
			);
			expect(put).toBeTruthy();
			expect(JSON.parse(String(put?.[1]?.body))).toEqual({
				transport: { mode: 'h2_only' },
			});
		});
	});

	it('titles a node by its display name and labels the node id as secondary text', async () => {
		renderPage();

		const row = (await screen.findByText('elmo')).closest('.row');
		if (!(row instanceof HTMLElement)) throw new Error('no node row');
		expect(within(row).getByText(/ID dns1/)).toBeInTheDocument();
		expect(screen.queryByText('dns1')).toBeNull();
	});

	it('revokes a node only after a confirmation that names it', async () => {
		const user = userEvent.setup();
		renderPage();

		const row = (await screen.findByText('elmo')).closest('.row');
		if (!(row instanceof HTMLElement)) throw new Error('no node row');
		const revoke = within(row).getByRole('button', { name: m.cluster_revoke() });
		expect(revoke).toHaveClass('quiet-danger');
		expect(revoke).not.toHaveClass('danger');

		await user.click(revoke);
		const dialog = await screen.findByRole('dialog', { name: m.cluster_revoke_title() });
		expect(within(dialog).getByText(/dns1/)).toBeInTheDocument();
		const deletes = () =>
			fetchMock.mock.calls.filter(([, init]) => (init?.method ?? '').toUpperCase() === 'DELETE');
		expect(deletes()).toEqual([]);

		await user.click(within(dialog).getByRole('button', { name: m.action_cancel() }));
		expect(screen.queryByRole('dialog')).toBeNull();
		expect(deletes()).toEqual([]);
	});

	it('shows the restart banner when restart_required is set', async () => {
		settingsBody = { ...baseSettings, restart_required: true };
		renderPage();
		expect(await screen.findByText(m.cluster_settings_restart_required())).toBeInTheDocument();
	});
});
