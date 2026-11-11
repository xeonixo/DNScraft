import { resolve } from '$app/paths';
import type { RouteId } from '$app/types';
import type { IconName } from '$lib/components/icons';
import { m } from '$lib/paraglide/messages';

/** Roles from SPEC-web-ui.md § Role gating. A viewer never sees an item that needs admin. */
export type Role = 'viewer' | 'admin';

/**
 * Routes that take no parameters. Navigation lists only these; a dynamic route (such as
 * /query-log/[id] or /dashboard/domains/[name]) is linked with resolve(route, params)
 * at the call site instead. The bare /dashboard/domains directory is not a screen.
 */
export type StaticRouteId = Exclude<
	RouteId,
	'/query-log/[id]' | '/dashboard/domains/[name]' | '/dashboard/domains'
>;

/**
 * `resolve()` is overloaded per route literal, so a `StaticRouteId` union does not match
 * one call signature. Cast once here for sidebar, settings tabs and palette links.
 */
export function routeHref(path: StaticRouteId): string {
	return (resolve as unknown as (route: StaticRouteId) => string)(path);
}

export interface NavItem {
	/** SvelteKit route path, also the key for the page title and the active item. */
	path: StaticRouteId;
	label: () => string;
	icon: IconName;
	minRole: Role;
}

export interface NavSection {
	heading: () => string;
	items: NavItem[];
}

const item = (
	path: StaticRouteId,
	label: () => string,
	icon: IconName,
	minRole: Role = 'viewer',
): NavItem => ({
	path,
	label,
	icon,
	minRole,
});

/** Sidebar sections in SPEC order (SPEC-web-ui.md § Navigation). */
export const navSections: NavSection[] = [
	{
		heading: () => m.nav_section_overview(),
		items: [
			item('/dashboard', () => m.nav_dashboard(), 'grid'),
			item('/query-log', () => m.nav_queries(), 'download'),
			item('/alerts', () => m.nav_alerts(), 'bell'),
		],
	},
	{
		heading: () => m.nav_section_filtering(),
		items: [
			item('/filter-sets', () => m.nav_filter_sets(), 'layers', 'admin'),
			item('/filter-lists', () => m.nav_filter_lists(), 'list', 'admin'),
			item('/rules', () => m.nav_rules(), 'zap', 'admin'),
			item('/blocked-services', () => m.nav_blocked_services(), 'ban'),
		],
	},
	{
		heading: () => m.nav_section_dns_rules(),
		items: [
			item('/zones', () => m.nav_zones(), 'target', 'admin'),
			item('/names', () => m.nav_names(), 'text', 'admin'),
			item('/forward-zones', () => m.nav_forward_zones(), 'arrow-right', 'admin'),
			item('/resolver', () => m.nav_resolver(), 'globe', 'admin'),
			item('/profiles', () => m.nav_profiles(), 'sliders', 'admin'),
			item('/test-query', () => m.nav_test_query(), 'play-circle'),
		],
	},
	{
		heading: () => m.nav_section_network(),
		items: [
			item('/clients', () => m.nav_clients(), 'user', 'admin'),
			item('/doh-clients', () => m.nav_doh_clients(), 'user-check', 'admin'),
			item('/listeners', () => m.nav_listeners(), 'network', 'admin'),
			item('/tls', () => m.nav_tls(), 'lock', 'admin'),
			item('/cluster', () => m.nav_nodes(), 'server', 'admin'),
		],
	},
];

/** Einstellungen is one item set apart below the sections (tabs live on the screen). */
export const navSettings = item('/settings', () => m.nav_settings(), 'settings');

/** Tabs of the Einstellungen screen group, in tab-bar order. Each tab is its own route. */
export const settingsTabs: { path: StaticRouteId; label: () => string }[] = [
	{ path: '/settings', label: () => m.settings_tab_general() },
	{ path: '/settings/config', label: () => m.settings_tab_configuration() },
	{ path: '/settings/mcp', label: () => m.settings_tab_mcp() },
	{ path: '/settings/api', label: () => m.settings_tab_api_explorer() },
];

/**
 * /feedback is routable and has a page title, but stays out of the sidebar and
 * command palette (opened from Help / deep links).
 */
const navFeedback = item('/feedback', () => m.feedback_title(), 'message-square');

const routed: NavItem[] = [
	...navSections.flatMap((section) => section.items),
	navSettings,
	navFeedback,
];

/** The nav entry for a route, used for the toolbar title, document title and placeholder icon. */
export function navItemForPath(pathname: string): NavItem | undefined {
	return (
		routed.find((entry) => entry.path === pathname) ??
		// Detail routes (for example /query-log/:id) belong to the section they open from.
		routed.find((entry) => pathname.startsWith(`${entry.path}/`))
	);
}

/**
 * Whether a nav entry is the current screen: its own path, or a sub-path of it. Einstellungen
 * tabs (/settings/config) and detail routes (/query-log/:id) keep their nav item active.
 */
export function isActivePath(entryPath: string, currentPath: string): boolean {
	return entryPath === currentPath || currentPath.startsWith(`${entryPath}/`);
}

export function isVisible(entry: NavItem, role: Role): boolean {
	return entry.minRole === 'viewer' || role === 'admin';
}
