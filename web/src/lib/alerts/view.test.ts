// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { m } from '$lib/paraglide/messages';
import { alertCodeHint, alertHref, alertTitle, groupAlerts } from './view';

describe('alertTitle', () => {
	it('translates known ids with params', () => {
		expect(
			alertTitle({
				id: 'resolver.upstream.down',
				severity: 'critical',
				module: 'resolver',
				params: { name: '1.1.1.1' },
				target_route: '/dashboard',
			}),
		).toBe(m.alert_resolver_upstream_down({ name: '1.1.1.1' }));
	});

	it('falls back to the raw id for unknown alerts', () => {
		expect(
			alertTitle({
				id: 'future.unknown',
				severity: 'warning',
				module: 'system',
				params: {},
				target_route: '/dashboard',
			}),
		).toBe('future.unknown');
	});

	it('explains known ACME codes in a sentence', () => {
		const item = {
			id: 'tls.engine.error',
			severity: 'warning',
			module: 'tls',
			params: { code: 'tls.acme.rate_limited' },
			target_route: '/tls',
		};
		expect(alertTitle(item)).toBe(m.alert_tls_acme_rate_limited());
		expect(alertCodeHint(item)).toBe('tls.acme.rate_limited');
	});

	it('keeps the raw code for unknown engine errors', () => {
		const item = {
			id: 'tls.engine.error',
			severity: 'warning',
			module: 'tls',
			params: { code: 'tls.acme.something_new' },
			target_route: '/tls',
		};
		expect(alertTitle(item)).toBe(m.alert_tls_engine_error({ code: 'tls.acme.something_new' }));
		expect(alertCodeHint(item)).toBeUndefined();
	});
});

describe('groupAlerts', () => {
	it('orders modules stably and keeps empty modules out', () => {
		const groups = groupAlerts([
			{
				id: 'cluster.node.offline',
				severity: 'warning',
				module: 'cluster',
				params: { node_id: 'n2' },
				target_route: '/cluster',
			},
			{
				id: 'system.not_ready',
				severity: 'critical',
				module: 'system',
				params: { modules: ['resolver'] },
				target_route: '/dashboard',
			},
		]);
		expect(groups.map((group) => group.module)).toEqual(['system', 'cluster']);
		expect(groups[0]?.items).toHaveLength(1);
	});
});

describe('alertHref', () => {
	it('accepts known target routes only', () => {
		expect(alertHref('/tls')).toBe('/tls');
		expect(alertHref('/not-a-screen')).toBeUndefined();
	});
});
