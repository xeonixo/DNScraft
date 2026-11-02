import { describe, expect, it } from 'vitest';
import {
	appliesToNode,
	dyndnsProfileForNode,
	listenersForNode,
	nodeLabel,
	nodeLag,
	viewsForNode,
} from './nodes';

describe('nodeLabel', () => {
	it('prefers the cluster display name and falls back to the id', () => {
		expect(nodeLabel('n1', { n1: 'Kitchen' })).toBe('Kitchen');
		expect(nodeLabel('n2', { n1: 'Kitchen' })).toBe('n2');
	});
});

describe('appliesToNode / scoped lists', () => {
	it('treats an empty nodes list as every node', () => {
		expect(appliesToNode([], 'n1')).toBe(true);
		expect(appliesToNode(['n2'], 'n1')).toBe(false);
		expect(appliesToNode(['n1', 'n2'], 'n1')).toBe(true);
	});

	it('filters listeners and views for a node', () => {
		const listeners = [
			{ id: 'all', nodes: [] as string[] },
			{ id: 'only-n1', nodes: ['n1'] },
			{ id: 'only-n2', nodes: ['n2'] },
		];
		expect(listenersForNode(listeners, 'n1').map((row) => row.id)).toEqual(['all', 'only-n1']);
		expect(viewsForNode([{ id: 'v', nodes: ['n2'] }], 'n1')).toEqual([]);
	});

	it('finds a DynDNS profile by node_id', () => {
		expect(
			dyndnsProfileForNode(
				[
					{ node_id: 'n1', hostname: 'a.example.com' },
					{ node_id: 'n2', hostname: 'b.example.com' },
				],
				'n2',
			)?.hostname,
		).toBe('b.example.com');
	});
});

describe('nodeLag', () => {
	it('measures each node against the newest applied version of the non-revoked nodes', () => {
		expect(
			nodeLag([
				{ applied_config_version: 5, revoked: false },
				{ applied_config_version: 3, revoked: false },
				{ applied_config_version: 9, revoked: true },
			]),
		).toEqual([0, 2, 0]);
	});

	it('counts a node without a reported version as fully behind', () => {
		expect(
			nodeLag([
				{ applied_config_version: 5, revoked: false },
				{ applied_config_version: null, revoked: false },
			]),
		).toEqual([0, 5]);
	});
});
