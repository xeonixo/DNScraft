// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { m } from '$lib/paraglide/messages';
import { navSections, navSettings, type NavSection, type Role } from '$lib/nav';
import { paletteEntries, type PaletteSource } from '$lib/palette/entries';
import CommandPalette from './CommandPalette.svelte';

const navigation = vi.hoisted(() => ({ goto: vi.fn() }));
vi.mock('$app/navigation', () => navigation);

const source: PaletteSource = {
	sections: [
		{
			heading: () => 'Test',
			items: [
				{ path: '/dashboard', label: () => 'Dashboard', icon: 'grid', minRole: 'viewer' },
				{ path: '/tls', label: () => 'Certificates', icon: 'lock', minRole: 'admin' },
			],
		},
	] satisfies NavSection[],
	settingsTabs: [],
};

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	navigation.goto.mockReset();
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

async function openPalette(user: ReturnType<typeof userEvent.setup>, chord = '{Meta>}k{/Meta}') {
	await user.keyboard(chord);
	const input = await screen.findByRole('combobox');
	await waitFor(() => expect(input).toHaveFocus());
	return input;
}

describe('Command palette', () => {
	it('palette_filters_by_role', async () => {
		const user = userEvent.setup();
		const viewer = render(CommandPalette, { props: { role: 'viewer', source } });
		await openPalette(user);
		expect(screen.getByRole('option', { name: 'Dashboard' })).toBeInTheDocument();
		expect(screen.queryByRole('option', { name: 'Certificates' })).not.toBeInTheDocument();
		viewer.unmount();

		render(CommandPalette, { props: { role: 'admin', source } });
		const input = await openPalette(user);
		expect(screen.getByRole('option', { name: 'Dashboard' })).toBeInTheDocument();
		expect(screen.getByRole('option', { name: 'Certificates' })).toBeInTheDocument();

		await user.type(input, 'cert');
		expect(screen.getByRole('option', { name: 'Certificates' })).toBeInTheDocument();
		expect(screen.queryByRole('option', { name: 'Dashboard' })).not.toBeInTheDocument();
	});

	it('palette_hides_admin_items_for_viewer', async () => {
		const user = userEvent.setup();
		render(CommandPalette, { props: { role: 'viewer', source } });
		const input = await openPalette(user);
		await user.type(input, 'cert');
		expect(screen.queryByRole('option', { name: 'Certificates' })).not.toBeInTheDocument();
		expect(screen.queryByRole('option', { name: 'Dashboard' })).not.toBeInTheDocument();
		expect(screen.getByText(m.palette_empty())).toBeInTheDocument();

		const adminPaths = [...navSections.flatMap((section) => section.items), navSettings]
			.filter((item) => item.minRole === 'admin')
			.map((item) => item.path);
		const shown = paletteEntries('viewer', '').map((entry) => entry.href);
		for (const path of adminPaths) {
			expect(shown.some((href) => href === path || href.endsWith(path))).toBe(false);
		}
	});

	it('palette_domain_maps_to_query_log_filter', async () => {
		const user = userEvent.setup();
		render(CommandPalette, { props: { role: 'viewer' satisfies Role, source } });
		const input = await openPalette(user);
		await user.type(input, 'ads.example.com');
		await user.keyboard('{Enter}');

		expect(navigation.goto).toHaveBeenCalledTimes(1);
		const href = String(navigation.goto.mock.calls[0][0]);
		const url = new URL(href, 'http://localhost');
		expect(url.pathname).toBe('/query-log');
		expect(url.searchParams.get('domain_substr')).toBe('ads.example.com');
		expect(url.searchParams.has('domain')).toBe(false);
		expect(href).not.toContain('/api/');
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('palette_combobox_aria_attributes', async () => {
		const user = userEvent.setup();
		render(CommandPalette, { props: { role: 'viewer' } });
		const input = await openPalette(user);
		const list = screen.getByRole('listbox');
		const options = screen.getAllByRole('option');

		expect(screen.getByRole('dialog')).toHaveAttribute('aria-modal', 'true');
		expect(input).toHaveAttribute('aria-expanded', 'true');
		expect(input).toHaveAttribute('aria-autocomplete', 'list');
		expect(input).toHaveAttribute('aria-controls', list.id);
		expect(input).toHaveAttribute('aria-activedescendant', options[0].id);
		expect(options[0]).toHaveAttribute('aria-selected', 'true');
		expect(options[1]).toHaveAttribute('aria-selected', 'false');
		expect(screen.getAllByRole('group').length).toBeGreaterThan(0);

		await user.keyboard('{ArrowDown}');
		expect(input).toHaveAttribute('aria-activedescendant', options[1].id);
		expect(options[1]).toHaveAttribute('aria-selected', 'true');

		await user.keyboard('{End}');
		expect(input).toHaveAttribute('aria-activedescendant', options[options.length - 1].id);
		await user.keyboard('{Home}');
		expect(input).toHaveAttribute('aria-activedescendant', options[0].id);
	});

	it('palette_typed_text_not_sent_to_server', async () => {
		const user = userEvent.setup();
		render(CommandPalette, { props: { role: 'viewer', source } });
		const input = await openPalette(user);
		await user.type(input, 'secret.example');
		await new Promise((resolveTimer) => setTimeout(resolveTimer, 50));

		expect(input).toHaveValue('secret.example');
		expect(fetchMock).not.toHaveBeenCalled();
		expect(navigation.goto).not.toHaveBeenCalled();
		expect(document.querySelector('form')).toBeNull();
		for (const node of document.querySelectorAll('[action], [href], [src]')) {
			const bag = `${node.getAttribute('action') ?? ''} ${node.getAttribute('href') ?? ''} ${node.getAttribute('src') ?? ''}`;
			expect(bag).not.toContain('secret.example');
		}
	});

	it('ignores Cmd and Ctrl+K in text fields, textareas, selects, and contenteditable', async () => {
		const user = userEvent.setup();
		render(CommandPalette, { props: { role: 'viewer', source } });
		await openPalette(user, '{Control>}k{/Control}');
		expect(screen.getByRole('dialog')).toBeInTheDocument();
		await user.keyboard('{Escape}');
		await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

		const text = document.createElement('input');
		const search = document.createElement('input');
		search.type = 'search';
		const area = document.createElement('textarea');
		const select = document.createElement('select');
		const editable = document.createElement('div');
		editable.contentEditable = 'true';
		editable.tabIndex = 0;
		for (const el of [text, search, area, select, editable]) {
			document.body.appendChild(el);
			el.focus();
			await user.keyboard('{Meta>}k{/Meta}');
			await user.keyboard('{Control>}k{/Control}');
			expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
			el.remove();
		}

		const box = document.createElement('input');
		box.type = 'checkbox';
		document.body.appendChild(box);
		box.focus();
		await openPalette(user);
		expect(screen.getByRole('dialog')).toBeInTheDocument();
		box.remove();
	});
});
