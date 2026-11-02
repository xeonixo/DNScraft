// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { live } from '$lib/live.svelte';
import { m } from '$lib/paraglide/messages';
import type { AuthSession } from '$lib/api/sessions';
import SessionsPanel from './SessionsPanel.svelte';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});

function session(overrides: Partial<AuthSession> = {}): AuthSession {
	return {
		id: 'sess-1',
		actor_id: 'alice',
		actor_type: 'user',
		role: 'admin',
		client_label: 'Firefox on macOS',
		ip: '192.0.2.0',
		created_at: '2026-10-01T00:00:00Z',
		last_seen: '2026-10-28T12:00:00Z',
		expires_at: '2026-11-01T00:00:00Z',
		current: false,
		...overrides,
	};
}

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
const deleted: string[] = [];

function serve(items: AuthSession[]): void {
	fetchMock.mockImplementation(async (input, init) => {
		const url = String(input);
		if ((init?.method ?? 'GET') === 'DELETE') {
			deleted.push(url);
			return json(200, { data: { id: 'other', revoked: true } });
		}
		if (url.includes('/api/v1/auth/sessions')) {
			return json(200, { data: { items, has_more: false, next_offset: null } });
		}
		return json(404, { error: { code: 'control_api.not_found' } });
	});
}

beforeEach(() => {
	deleted.length = 0;
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	endSession();
	live.message = '';
	setPrincipal({ role: 'admin', actorId: 'alice', actorType: 'user', csrfToken: 'tok' });
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function rowOf(label: string): HTMLElement {
	const row = screen.getByText(label).closest('.row');
	if (!(row instanceof HTMLElement)) throw new Error(`no row for ${label}`);
	return row;
}

describe('active sessions', () => {
	const current = session({ id: 'current', client_label: 'Firefox on macOS', current: true });
	const other = session({
		id: 'other',
		actor_id: 'bob',
		role: 'viewer',
		client_label: 'Chrome on Windows',
		ip: '198.51.100.0',
		current: false,
	});

	it('current_session_badge_and_no_revoke_for_current', async () => {
		serve([current, other]);
		render(SessionsPanel, { props: { isAdmin: true } });

		expect(await screen.findByText(m.settings_sessions_current())).toBeInTheDocument();
		expect(
			within(rowOf('Firefox on macOS')).queryByRole('button', {
				name: m.settings_sessions_revoke(),
			}),
		).toBeNull();
		expect(
			within(rowOf('Chrome on Windows')).getByRole('button', {
				name: m.settings_sessions_revoke(),
			}),
		).toBeInTheDocument();
		expect(screen.getByText(/bob/)).toBeInTheDocument();
		expect(String(fetchMock.mock.calls[0]?.[0])).toContain('scope=all');
	});

	it('asks before revoking another session', async () => {
		serve([current, other]);
		const user = userEvent.setup();
		render(SessionsPanel, { props: { isAdmin: true } });

		await screen.findByText('Chrome on Windows');
		await user.click(
			within(rowOf('Chrome on Windows')).getByRole('button', {
				name: m.settings_sessions_revoke(),
			}),
		);
		const dialog = await screen.findByRole('dialog', { name: m.settings_sessions_revoke_title() });
		expect(deleted).toEqual([]);
		expect(within(dialog).getByText(/Chrome on Windows/)).toBeInTheDocument();
		await user.click(within(dialog).getByRole('button', { name: m.action_cancel() }));
		expect(screen.queryByRole('dialog')).toBeNull();
		expect(deleted).toEqual([]);

		await user.click(
			within(rowOf('Chrome on Windows')).getByRole('button', {
				name: m.settings_sessions_revoke(),
			}),
		);
		await user.click(
			within(screen.getByRole('dialog')).getByRole('button', {
				name: m.settings_sessions_revoke(),
			}),
		);
		await waitFor(() => expect(deleted).toEqual(['/api/v1/auth/sessions/other']));
		expect(live.message).toBe(m.settings_sessions_revoked());
	});

	it('lists only the viewer’s own sessions and hides the actor', async () => {
		setPrincipal({ role: 'viewer', actorId: 'carol', actorType: 'user', csrfToken: 'tok' });
		serve([session({ actor_id: 'carol', role: 'viewer', client_label: 'Safari on macOS' })]);
		render(SessionsPanel, { props: { isAdmin: false } });

		expect(await screen.findByText('Safari on macOS')).toBeInTheDocument();
		expect(screen.queryByText('carol')).toBeNull();
		expect(
			screen.queryByRole('radiogroup', { name: m.settings_sessions_scope_label() }),
		).toBeNull();
		expect(String(fetchMock.mock.calls[0]?.[0])).toContain('scope=own');
	});

	it('renders a client label as text', async () => {
		const hostile = '<img src=x onerror=alert(1)>';
		serve([session({ client_label: hostile, current: true })]);
		const { container } = render(SessionsPanel, { props: { isAdmin: false } });

		expect(await screen.findByText(hostile)).toBeInTheDocument();
		expect(container.querySelector('img')).toBeNull();
	});
});
