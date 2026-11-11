import { ApiError, get, isRecord, post } from './client';
import { CLIENT_MALFORMED } from './error-codes';
import { NOT_READY_CODE } from './result';

// Typed reads and writes for the dashboard. Only the fields the UI renders are declared; shapes
// follow the handlers in crates/dnscraft-api (stats_routes.rs, resolver_routes.rs, router.rs).

export type TlsMode = 'acme' | 'manual' | 'self_signed';
export type Period = '24h' | '7d' | '30d' | '1y';
export type PauseDuration = 'PT5M' | 'PT15M' | 'PT1H';
export type UpstreamState = 'up' | 'degraded' | 'down' | 'unknown';

/** Filter set the pause and resume endpoints default to when no id is sent. */
export const FILTER_SET = 'default';

export const PERIODS: readonly Period[] = ['24h', '7d', '30d', '1y'];

const DAY_MS = 86_400_000;
const PERIOD_MS: Record<Period, number> = {
	'24h': DAY_MS,
	'7d': 7 * DAY_MS,
	'30d': 30 * DAY_MS,
	'1y': 365 * DAY_MS,
};

export interface StatusCluster {
	role: string;
	/** This node's cluster id; absent on older servers. */
	node_id?: string;
	master_reachable: boolean;
	applied_version: number | null;
	lag: number;
	queue_depth: number;
	last_sync: string | null;
	degraded_nodes: number;
}

export interface StatusData {
	version: string;
	ready: boolean;
	modules_not_ready: string[];
	tls_mode?: TlsMode;
	tls_fingerprint?: string;
	tls?: { identifiers?: string[] };
	cluster?: StatusCluster;
}

export interface Readiness {
	ready: boolean;
	modules: string[];
}

export interface StatsOverview {
	source: 'raw' | 'rollup';
	total: number;
	allowed: number;
	blocked: number;
	allowed_ratio: number;
	query_log_dropped: number;
	by_answer_source: Record<string, number>;
}

export interface TopDomain {
	domain: string;
	queries: number;
	blocked: number;
}

export interface TopClient {
	client_id: string;
	client_name: string;
	queries: number;
	blocked: number;
}

export interface CacheStats {
	hits: number;
	misses: number;
	hit_ratio: number;
}

export interface Upstream {
	name: string;
	kind: 'forward_target' | 'recursion';
	zone: string | null;
	protocol: string;
	state: UpstreamState;
	rtt_ms: { p50: number; p95: number } | null;
	success_rate: number | null;
	samples: number;
	last_error: { code: string } | null;
	last_checked: string | null;
}

export interface UpstreamsData {
	window_seconds: number;
	items: Upstream[];
}

export interface FlushResult {
	scope: 'all' | 'domain';
	domain: string | null;
	evicted: number;
}

export interface PauseResult {
	filter_set_id: string;
	paused_until: string;
}

/** `from` and `to` as RFC 3339 instants for the period ending at `now`. */
export function periodQuery(period: Period, now: Date = new Date()): string {
	const to = now.getTime();
	const from = to - PERIOD_MS[period];
	return new URLSearchParams({
		from: new Date(from).toISOString(),
		to: new Date(to).toISOString(),
	}).toString();
}

export const getStatus = (): Promise<StatusData> => get<StatusData>('/status');

/** `GET /readyz` is outside `/api/v1`. A 503 `not_ready` is an answer with the starting modules. */
export async function getReadiness(): Promise<Readiness> {
	try {
		await get<unknown>('/readyz', { root: true, public: true });
		return { ready: true, modules: [] };
	} catch (cause) {
		if (cause instanceof ApiError && cause.code === NOT_READY_CODE) {
			const modules = cause.params.modules;
			return {
				ready: false,
				modules: Array.isArray(modules)
					? modules.filter((item): item is string => typeof item === 'string')
					: [],
			};
		}
		throw cause;
	}
}

export const getOverview = (period: Period, now?: Date): Promise<StatsOverview> =>
	get<StatsOverview>(`/stats/overview?${periodQuery(period, now)}`);

export const getTopDomains = (period: Period, limit: number, now?: Date): Promise<TopDomain[]> =>
	get<{ domains: TopDomain[] }>(
		`/stats/top_domains?${periodQuery(period, now)}&limit=${limit}`,
	).then((data) => data.domains);

/** Domains ranked by blocked count (not by total queries). */
export const getTopBlockedDomains = (
	period: Period,
	limit: number,
	now?: Date,
): Promise<TopDomain[]> =>
	get<{ domains: TopDomain[] }>(
		`/stats/top_blocked_domains?${periodQuery(period, now)}&limit=${limit}`,
	).then((data) => data.domains);

export const getTopClients = (period: Period, limit: number, now?: Date): Promise<TopClient[]> =>
	get<{ clients: TopClient[] }>(
		`/stats/top_clients?${periodQuery(period, now)}&limit=${limit}`,
	).then((data) => data.clients);

export const getCacheStats = (period: Period, now?: Date): Promise<CacheStats> =>
	get<CacheStats>(`/stats/cache?${periodQuery(period, now)}`);

export const getUpstreams = (): Promise<UpstreamsData> => get<UpstreamsData>('/resolver/upstreams');

/** Admin. An absent domain flushes the whole cache; a domain also removes everything below it. */
export const flushCache = (domain: string | null): Promise<FlushResult> =>
	post<FlushResult>('/resolver/cache/flush', { body: domain === null ? {} : { domain } });

/** Admin. Pauses blocking on one filter set for a fixed duration; audited by the server. */
export const pauseFilterSet = (duration: PauseDuration): Promise<PauseResult> =>
	post<PauseResult>('/filtering/pause', {
		body: { filter_set_id: FILTER_SET, duration },
	});

/** Window of `GET /api/v1/stats/domains/{name}`. */
export type DomainDays = 7 | 30;

export interface DomainClientStat {
	client: string;
	queries: number;
}

export interface DomainDayStat {
	day: string;
	total: number;
	blocked: number;
}

export interface DomainLastDecision {
	id: string;
	time: string;
	status: string;
	rule_text: string | null;
	source: string | null;
}

/** Body of `GET /api/v1/stats/domains/{name}` (`QueryLog::domain_detail`). */
export interface DomainStats {
	domain: string;
	retention_limited: boolean;
	first_seen: string;
	last_seen: string;
	counts: { total: number; blocked: number; allowed: number };
	top_clients: DomainClientStat[];
	daily: DomainDayStat[];
	last_decision: DomainLastDecision | null;
}

function finite(value: unknown): number {
	if (typeof value !== 'number' || !Number.isFinite(value)) throw new ApiError(0, CLIENT_MALFORMED);
	return value;
}

function parseClients(value: unknown): DomainClientStat[] {
	if (!Array.isArray(value)) throw new ApiError(0, CLIENT_MALFORMED);
	return value.map((item) => {
		if (!isRecord(item) || typeof item.client !== 'string') throw new ApiError(0, CLIENT_MALFORMED);
		return { client: item.client, queries: finite(item.queries) };
	});
}

function parseDaily(value: unknown): DomainDayStat[] {
	if (!Array.isArray(value)) throw new ApiError(0, CLIENT_MALFORMED);
	return value.map((item) => {
		if (!isRecord(item) || typeof item.day !== 'string') throw new ApiError(0, CLIENT_MALFORMED);
		return { day: item.day, total: finite(item.total), blocked: finite(item.blocked) };
	});
}

function parseDecision(value: unknown): DomainLastDecision | null {
	if (value === null) return null;
	if (!isRecord(value) || typeof value.id !== 'string') throw new ApiError(0, CLIENT_MALFORMED);
	return {
		id: value.id,
		time: typeof value.time === 'string' ? value.time : '',
		status: typeof value.status === 'string' ? value.status : '',
		rule_text: typeof value.rule_text === 'string' ? value.rule_text : null,
		source: typeof value.source === 'string' ? value.source : null,
	};
}

/** One domain over the raw query log. `days` is 7 or 30; an unseen name is a 404. */
export async function getDomainStats(name: string, days: DomainDays = 7): Promise<DomainStats> {
	const data = await get<unknown>(`/stats/domains/${encodeURIComponent(name)}?days=${days}`);
	if (
		!isRecord(data) ||
		typeof data.domain !== 'string' ||
		typeof data.retention_limited !== 'boolean' ||
		typeof data.first_seen !== 'string' ||
		typeof data.last_seen !== 'string' ||
		!isRecord(data.counts)
	) {
		throw new ApiError(0, CLIENT_MALFORMED);
	}
	return {
		domain: data.domain,
		retention_limited: data.retention_limited,
		first_seen: data.first_seen,
		last_seen: data.last_seen,
		counts: {
			total: finite(data.counts.total),
			blocked: finite(data.counts.blocked),
			allowed: finite(data.counts.allowed),
		},
		top_clients: parseClients(data.top_clients),
		daily: parseDaily(data.daily),
		last_decision: parseDecision(data.last_decision),
	};
}
