import type { AlertItem } from '$lib/api/alerts';
import type { StaticRouteId } from '$lib/nav';
import { m } from '$lib/paraglide/messages';

const MODULE_ORDER = [
	'system',
	'resolver',
	'tls',
	'filtering',
	'cluster',
	'listeners',
	'clients',
	'querylog',
] as const;

const KNOWN_ROUTES = new Set<string>([
	'/dashboard',
	'/tls',
	'/filter-lists',
	'/cluster',
	'/listeners',
	'/clients',
	'/query-log',
	'/settings',
	'/settings/config',
]);

/** Known ACME error codes from `tls.engine.error`, with a human sentence each. */
const TLS_ENGINE_CODES = new Map<string, () => string>([
	['tls.acme.rate_limited', () => m.alert_tls_acme_rate_limited()],
	['tls.acme.account', () => m.alert_tls_acme_account()],
	['tls.acme.challenge', () => m.alert_tls_acme_challenge()],
	['tls.acme.order', () => m.alert_tls_acme_order()],
	['tls.acme.order_pending', () => m.alert_tls_acme_order_pending()],
	['tls.acme.propagation', () => m.alert_tls_acme_propagation()],
]);

export type AlertModule = (typeof MODULE_ORDER)[number] | string;

export interface AlertGroup {
	module: AlertModule;
	heading: string;
	items: AlertItem[];
}

function paramString(params: Record<string, unknown>, key: string): string | undefined {
	const value = params[key];
	return typeof value === 'string' ? value : undefined;
}

function paramNumber(params: Record<string, unknown>, key: string): number | undefined {
	const value = params[key];
	return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function paramModules(params: Record<string, unknown>): string {
	const value = params.modules;
	if (!Array.isArray(value)) return '';
	return value.filter((item): item is string => typeof item === 'string').join(', ');
}

/** Translated title for an alert id; falls back to the raw id. */
export function alertTitle(item: AlertItem): string {
	const { id, params } = item;
	switch (id) {
		case 'system.not_ready':
			return m.alert_system_not_ready({ modules: paramModules(params) });
		case 'system.backup.failed':
			return m.alert_system_backup_failed({ code: paramString(params, 'code') ?? '—' });
		case 'system.update.unreachable':
			return m.alert_system_update_unreachable();
		case 'resolver.upstream.down':
			return m.alert_resolver_upstream_down({ name: paramString(params, 'name') ?? '—' });
		case 'resolver.upstream.degraded':
			return m.alert_resolver_upstream_degraded({ name: paramString(params, 'name') ?? '—' });
		case 'resolver.priming.fallback':
			return m.alert_resolver_priming_fallback();
		case 'tls.cert.revoked':
			return m.alert_tls_cert_revoked();
		case 'tls.cert.expired':
			return m.alert_tls_cert_expired();
		case 'tls.cert.expiring':
			return m.alert_tls_cert_expiring({
				days: String(paramNumber(params, 'days_to_expiry') ?? '—'),
			});
		case 'tls.dyndns.stale':
			return m.alert_tls_dyndns_stale();
		case 'tls.bootstrap.self_signed':
			return m.alert_tls_bootstrap_self_signed();
		case 'tls.store.corrupt':
			return m.alert_tls_store_corrupt();
		case 'tls.engine.error': {
			const code = paramString(params, 'code');
			const known = code === undefined ? undefined : TLS_ENGINE_CODES.get(code);
			return known ? known() : m.alert_tls_engine_error({ code: code ?? '—' });
		}
		case 'tls.dns.conflict':
			return m.alert_tls_dns_conflict({
				count: String(paramNumber(params, 'count') ?? 0),
			});
		case 'tls.secret.missing':
			return m.alert_tls_secret_missing();
		case 'filtering.list.update_failed':
			return m.alert_filtering_list_update_failed({
				list: paramString(params, 'list_id') ?? '—',
				code: paramString(params, 'code') ?? '—',
			});
		case 'cluster.master.unreachable':
			return m.alert_cluster_master_unreachable();
		case 'cluster.node.offline':
			return m.alert_cluster_node_offline({ node: paramString(params, 'node_id') ?? '—' });
		case 'cluster.node.disconnected':
			return m.alert_cluster_node_disconnected({ node: paramString(params, 'node_id') ?? '—' });
		case 'cluster.sync.degraded':
			return m.alert_cluster_sync_degraded({ count: String(paramNumber(params, 'count') ?? 0) });
		case 'cluster.config.lag':
			return m.alert_cluster_config_lag({ lag: String(paramNumber(params, 'lag') ?? 0) });
		case 'cluster.apply_failed':
			return m.alert_cluster_apply_failed({ error: paramString(params, 'error') ?? '—' });
		case 'cluster.clock_skew':
			return m.alert_cluster_clock_skew();
		case 'cluster.master_conflict':
			return m.alert_cluster_master_conflict();
		case 'cluster.config.stale':
			return m.alert_cluster_config_stale();
		case 'cluster.offline_write_queue_full':
			return m.alert_cluster_offline_write_queue_full();
		case 'listeners.bind_failed':
			return m.alert_listeners_bind_failed({
				id: paramString(params, 'listener_id') ?? '—',
				code: paramString(params, 'code') ?? '—',
			});
		case 'clients.unifi.sync_failed':
			return m.alert_clients_unifi_sync_failed({ code: paramString(params, 'code') ?? '—' });
		case 'clients.unifi.ip_conflicts':
			return m.alert_clients_unifi_ip_conflicts({
				count: String(paramNumber(params, 'count') ?? 0),
			});
		case 'querylog.dropped':
			return m.alert_querylog_dropped({ count: String(paramNumber(params, 'count') ?? 0) });
		default:
			return id;
	}
}

/** Raw code to show as small secondary text, only when alertTitle has a human sentence for it. */
export function alertCodeHint(item: AlertItem): string | undefined {
	if (item.id !== 'tls.engine.error') return undefined;
	const code = paramString(item.params, 'code');
	return code !== undefined && TLS_ENGINE_CODES.has(code) ? code : undefined;
}

export function alertSeverityLabel(severity: string): string {
	return severity === 'critical' ? m.alert_severity_critical() : m.alert_severity_warning();
}

export function moduleHeading(module: string): string {
	switch (module) {
		case 'system':
			return m.alert_module_system();
		case 'resolver':
			return m.alert_module_resolver();
		case 'tls':
			return m.alert_module_tls();
		case 'filtering':
			return m.alert_module_filtering();
		case 'cluster':
			return m.alert_module_cluster();
		case 'listeners':
			return m.alert_module_listeners();
		case 'clients':
			return m.alert_module_clients();
		case 'querylog':
			return m.alert_module_querylog();
		default:
			return module;
	}
}

/** Groups alerts by module in a stable order. */
export function groupAlerts(items: AlertItem[]): AlertGroup[] {
	const buckets = new Map<string, AlertItem[]>();
	for (const item of items) {
		const list = buckets.get(item.module) ?? [];
		list.push(item);
		buckets.set(item.module, list);
	}
	const groups: AlertGroup[] = [];
	for (const module of MODULE_ORDER) {
		const list = buckets.get(module);
		if (!list?.length) continue;
		groups.push({ module, heading: moduleHeading(module), items: list });
		buckets.delete(module);
	}
	for (const [module, list] of buckets) {
		groups.push({ module, heading: moduleHeading(module), items: list });
	}
	return groups;
}

/** Route usable by GroupedRow, or undefined when the API path is unknown. */
export function alertHref(target: string): StaticRouteId | undefined {
	if (!KNOWN_ROUTES.has(target)) return undefined;
	return target as StaticRouteId;
}
