// Client-side command palette index. Matching stays in the browser: the typed text is never a
// request. A domain-like query links to the query log with the same `domain_substr` parameter the
// search box writes (FilterForm).

import { m } from '$lib/paraglide/messages';
import type { FilterKey } from '$lib/querylog/filters';
import { listHref } from '$lib/querylog/saved';
import {
	isVisible,
	navFeedback,
	navSections,
	routeHref,
	settingsTabs,
	type NavItem,
	type NavSection,
	type Role,
	type StaticRouteId,
} from '$lib/nav';

export type PaletteSection = 'navigation' | 'domains';

export interface PaletteEntry {
	id: string;
	label: string;
	section: PaletteSection;
	/** App route. Never an API path. */
	href: string;
}

export interface PaletteSource {
	sections: NavSection[];
	settingsTabs: { path: StaticRouteId; label: () => string }[];
	feedback: NavItem | null;
}

/** Query-log search parameter. `satisfies` keeps this tied to the filter draft. */
const DOMAIN_FILTER = 'domain_substr' satisfies FilterKey;

const LABEL = /^[\p{L}\p{N}_](?:[\p{L}\p{N}_-]{0,61}[\p{L}\p{N}_])?$/u;

function defaultSource(): PaletteSource {
	return { sections: navSections, settingsTabs, feedback: navFeedback };
}

/**
 * Hostname-like text (letters, a dot, DNS labels), or null. Trailing dot is stripped.
 * Numeric versions (`1.2.3`) and sentences are not domains.
 */
export function domainText(value: string): string | null {
	const text = value.trim().replace(/\.$/, '');
	if (text.length < 3 || text.length > 253 || !text.includes('.') || !/\p{L}/u.test(text))
		return null;
	const labels = text.split('.');
	if (!labels.every((label) => LABEL.test(label))) return null;
	return text;
}

function queryLogHref(domain: string): string {
	const params = new URLSearchParams();
	params.set(DOMAIN_FILTER, domain);
	return listHref(params.toString());
}

/** Nav entries the role may see, plus a query-log hit when the query is a domain. */
export function paletteEntries(
	role: Role,
	query: string,
	source: PaletteSource = defaultSource(),
): PaletteEntry[] {
	const needle = query.trim().toLowerCase();
	const navigation: PaletteEntry[] = [];

	const push = (item: NavItem, label = item.label()): void => {
		if (!isVisible(item, role)) return;
		if (needle !== '' && !label.toLowerCase().includes(needle)) return;
		navigation.push({
			id: `nav:${item.path}:${label}`,
			label,
			section: 'navigation',
			href: routeHref(item.path),
		});
	};

	for (const section of source.sections) {
		for (const item of section.items) push(item);
	}
	const settingsLabel = m.nav_settings();
	for (const tab of source.settingsTabs) {
		push(
			{ path: tab.path, label: tab.label, icon: 'settings', minRole: 'viewer' },
			`${settingsLabel} › ${tab.label()}`,
		);
	}
	if (source.feedback) push(source.feedback);

	const domain = domainText(query);
	if (domain === null) return navigation;
	return [
		{
			id: `domain:${domain}`,
			label: m.palette_domain_search({ domain }),
			section: 'domains',
			href: queryLogHref(domain),
		},
		...navigation,
	];
}
