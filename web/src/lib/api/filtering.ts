import { ApiError, del, get, isRecord, post, put, type RequestOptions } from './client';
import { CLIENT_MALFORMED } from './error-codes';

export type BlockMode = 'refused' | 'nxdomain' | 'null_ip' | { custom_ip: string };

export interface FilterSet {
	id: string;
	name: string;
	lists: string[];
	custom_rules: string;
	services: string[];
	block_mode: BlockMode;
}

/** Per-list engine status as `GET /api/v1/filter-lists` returns it (absent for disabled or never-fetched lists). */
export interface FilterListStatus {
	rules_parsed: number;
	rules_skipped: number;
	unique_contribution: number;
	last_success: string | null;
	last_attempt: string | null;
	error_code: string | null;
	http_status: number | null;
}

export interface FilterList {
	id: string;
	name: string;
	source: { url?: string; file?: string };
	enabled: boolean;
	status?: FilterListStatus;
}

export interface GuidedRule {
	action: 'block' | 'allow';
	domain: string;
	include_subdomains: boolean;
}

export interface CustomRuleBody {
	domain: string;
	include_subdomains: boolean;
	filter_set_id: string;
	reason?: string;
}

export function buildRuleText(rule: GuidedRule): string {
	// Matches crates/dnscraft-filtering builder.rs: `||` covers subdomains, `|` anchors the exact name.
	const body = `${rule.include_subdomains ? '||' : '|'}${rule.domain}^`;
	return rule.action === 'allow' ? `@@${body}` : body;
}

function parseSet(value: unknown): FilterSet | null {
	if (typeof value !== 'object' || value === null) return null;
	const row = value as FilterSet;
	if (typeof row.id !== 'string') return null;
	return {
		id: row.id,
		name: typeof row.name === 'string' ? row.name : '',
		lists: Array.isArray(row.lists) ? row.lists.map(String) : [],
		custom_rules:
			typeof row.custom_rules === 'string'
				? row.custom_rules
				: Array.isArray(row.custom_rules)
					? (row.custom_rules as string[]).join('\n')
					: '',
		services: Array.isArray(row.services) ? row.services.map(String) : [],
		block_mode: row.block_mode ?? 'refused',
	};
}

function parseStatus(value: unknown): FilterListStatus | undefined {
	if (typeof value !== 'object' || value === null) return undefined;
	const row = value as Record<string, unknown>;
	if (typeof row.rules_parsed !== 'number') return undefined;
	const text = (field: unknown): string | null => (typeof field === 'string' ? field : null);
	return {
		rules_parsed: row.rules_parsed,
		rules_skipped: typeof row.rules_skipped === 'number' ? row.rules_skipped : 0,
		unique_contribution: typeof row.unique_contribution === 'number' ? row.unique_contribution : 0,
		last_success: text(row.last_success),
		last_attempt: text(row.last_attempt),
		error_code: text(row.error_code),
		http_status: typeof row.http_status === 'number' ? row.http_status : null,
	};
}

function parseList(value: unknown): FilterList | null {
	if (typeof value !== 'object' || value === null) return null;
	const row = value as FilterList;
	if (typeof row.id !== 'string') return null;
	const source =
		typeof row.source === 'object' && row.source !== null
			? (row.source as FilterList['source'])
			: {};
	const status = parseStatus((row as { status?: unknown }).status);
	return {
		id: row.id,
		name: typeof row.name === 'string' ? row.name : '',
		source,
		enabled: row.enabled !== false,
		...(status ? { status } : {}),
	};
}

export const listFilterSets = (): Promise<FilterSet[]> =>
	get<{ filter_sets: unknown }>('/filter-sets').then((data) =>
		Array.isArray(data.filter_sets)
			? data.filter_sets.map(parseSet).filter((s): s is FilterSet => s !== null)
			: [],
	);

export const saveFilterSet = (
	body: FilterSet,
	options?: RequestOptions,
): Promise<{ version: number; filter_set: FilterSet; created: boolean }> =>
	put('/filter-sets', { body, ...options });

export const deleteFilterSet = (
	id: string,
	options?: RequestOptions,
): Promise<{ version: number }> => del('/filter-sets', { body: { id }, ...options });

export const listFilterLists = (): Promise<FilterList[]> =>
	get<{ filter_lists: unknown }>('/filter-lists').then((data) =>
		Array.isArray(data.filter_lists)
			? data.filter_lists.map(parseList).filter((l): l is FilterList => l !== null)
			: [],
	);

export const saveFilterList = (
	body: FilterList,
	options?: RequestOptions,
): Promise<{ version: number; filter_list: FilterList; created: boolean }> =>
	put('/filter-lists', { body, ...options });

export const deleteFilterList = (
	id: string,
	options?: RequestOptions,
): Promise<{ version: number }> => del('/filter-lists', { body: { id }, ...options });

export const addCustomRule = (
	body: CustomRuleBody,
): Promise<{ rule_text: string; domain: string; include_subdomains: boolean }> =>
	post('/filtering/custom-rules', { body });

/** One catalog row from `GET /api/v1/filtering/services`. Icons are not part of the payload. */
export interface BlockedService {
	id: string;
	name: string;
	group: string;
	group_id: string;
	/** Whether the service is blocked in each filter set. */
	enabled: Record<string, boolean>;
}

/** `GET /api/v1/filtering/services`. `available` is false when no catalog is loaded. */
export interface BlockedServicesCatalog {
	available: boolean;
	catalog_updated_at: string | null;
	locale: string;
	items: BlockedService[];
}

export interface ServiceToggle {
	filter_set_id: string;
	enabled: boolean;
}

function parseEnabled(value: unknown): Record<string, boolean> {
	if (!isRecord(value)) return {};
	const enabled: Record<string, boolean> = {};
	for (const [id, flag] of Object.entries(value)) {
		if (typeof flag === 'boolean') enabled[id] = flag;
	}
	return enabled;
}

function parseService(value: unknown): BlockedService | null {
	if (!isRecord(value) || typeof value.id !== 'string' || value.id === '') return null;
	return {
		id: value.id,
		name: typeof value.name === 'string' ? value.name : '',
		group: typeof value.group === 'string' ? value.group : '',
		group_id: typeof value.group_id === 'string' ? value.group_id : '',
		enabled: parseEnabled(value.enabled),
	};
}

function parseServicesCatalog(data: unknown): BlockedServicesCatalog {
	if (!isRecord(data)) throw new ApiError(0, CLIENT_MALFORMED);
	return {
		available: data.available === true,
		catalog_updated_at:
			typeof data.catalog_updated_at === 'string' ? data.catalog_updated_at : null,
		locale: typeof data.locale === 'string' ? data.locale : '',
		items: Array.isArray(data.items)
			? data.items.map(parseService).filter((item): item is BlockedService => item !== null)
			: [],
	};
}

/** Catalog for the viewer's locale. Names and groups are already translated by the API. */
export const getServices = (locale: string): Promise<BlockedServicesCatalog> =>
	get<unknown>(`/filtering/services?locale=${encodeURIComponent(locale)}`).then(
		parseServicesCatalog,
	);

/** Blocks or allows one service in one filter set (admin). */
export const putService = (
	serviceId: string,
	body: ServiceToggle,
	options?: RequestOptions,
): Promise<ServiceToggle & { version: number; service_id: string }> =>
	put(`/filtering/services/${encodeURIComponent(serviceId)}`, { body, ...options });
