<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import { getConfig } from '$lib/api/config';
	import { listListeners, type Listener } from '$lib/api/listeners';
	import { listViews, type PolicyView } from '$lib/api/policy';
	import { getTlsConfig } from '$lib/api/tls';
	import { failureOf } from '$lib/api/result';
	import { announce } from '$lib/live.svelte';
	import { patchConfigSection } from '$lib/settings/config-patch';
	import { dyndnsProfileForNode, listenersForNode, viewsForNode } from '$lib/cluster/nodes';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		nodeId: string;
		isAdmin: boolean;
	}

	let { nodeId, isAdmin }: Props = $props();

	type DynDnsWire = {
		node_id: string;
		hostname?: string;
		enabled?: boolean;
		public_entry?: boolean;
	};

	let listeners = $state<Listener[]>([]);
	let views = $state<PolicyView[]>([]);
	let profiles = $state<{ id: string }[]>([]);
	let binding = $state('');
	let dyndns = $state<DynDnsWire | null>(null);
	let loaded = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	const scopedListeners = $derived(listenersForNode(listeners, nodeId));
	const scopedViews = $derived(viewsForNode(views, nodeId));

	onMount(() => {
		void load();
	});

	async function load(): Promise<void> {
		failure = null;
		try {
			const [listenerRows, viewRows, tls, snapshot] = await Promise.all([
				listListeners().catch(() => [] as Listener[]),
				listViews().catch(() => [] as PolicyView[]),
				getTlsConfig().catch(() => null),
				getConfig(),
			]);
			listeners = listenerRows;
			views = viewRows;
			const clients = (snapshot.config?.clients ?? {}) as Record<string, unknown>;
			const rawProfiles = Array.isArray(clients.unifi_profiles) ? clients.unifi_profiles : [];
			profiles = rawProfiles
				.map((row) => {
					const id =
						typeof (row as { id?: unknown }).id === 'string' ? (row as { id: string }).id : '';
					return id ? { id } : null;
				})
				.filter((row): row is { id: string } => row !== null);
			const bindings = (clients.unifi_bindings ?? {}) as Record<string, unknown>;
			binding = typeof bindings[nodeId] === 'string' ? (bindings[nodeId] as string) : '';
			const dyndnsSection = ((tls?.tls as Record<string, unknown> | undefined)?.dyndns ??
				{}) as Record<string, unknown>;
			const nodes = Array.isArray(dyndnsSection.nodes) ? (dyndnsSection.nodes as DynDnsWire[]) : [];
			dyndns = dyndnsProfileForNode(nodes, nodeId) ?? null;
			loaded = true;
		} catch (cause) {
			failure = failureOf(cause);
			loaded = true;
		}
	}

	async function saveBinding(next: string): Promise<void> {
		if (!isAdmin) return;
		busy = true;
		failure = null;
		const previous = binding;
		binding = next;
		try {
			const snapshot = await getConfig();
			const clients = {
				...((snapshot.config?.clients as Record<string, unknown> | undefined) ?? {}),
			};
			const bindings = {
				...((clients.unifi_bindings as Record<string, string> | undefined) ?? {}),
			};
			if (!next) delete bindings[nodeId];
			else bindings[nodeId] = next;
			await patchConfigSection('clients', { ...clients, unifi_bindings: bindings });
			announce(m.cluster_hub_unifi_saved());
		} catch (cause) {
			binding = previous;
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function toggleDyndns(enabled: boolean): Promise<void> {
		if (!isAdmin || !dyndns) return;
		busy = true;
		failure = null;
		const previous = dyndns.enabled === true;
		dyndns = { ...dyndns, enabled };
		try {
			const snapshot = await getConfig();
			const tls = {
				...((snapshot.config?.tls as Record<string, unknown> | undefined) ?? {}),
			};
			const dyndnsSection = {
				...((tls.dyndns as Record<string, unknown> | undefined) ?? {}),
			};
			const nodes = Array.isArray(dyndnsSection.nodes)
				? [...(dyndnsSection.nodes as Record<string, unknown>[])]
				: [];
			const index = nodes.findIndex((row) => row.node_id === nodeId);
			if (index >= 0) nodes[index] = { ...nodes[index], enabled };
			else nodes.push({ node_id: nodeId, enabled, hostname: dyndns.hostname ?? '' });
			await patchConfigSection('tls', { ...tls, dyndns: { ...dyndnsSection, nodes } });
			announce(enabled ? m.cluster_hub_dyndns_on() : m.cluster_hub_dyndns_off());
		} catch (cause) {
			dyndns = { ...dyndns, enabled: previous };
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	function listenersHref(): string {
		return `${resolve('/listeners')}?node=${encodeURIComponent(nodeId)}`;
	}

	function zonesHref(): string {
		return `${resolve('/zones')}?node=${encodeURIComponent(nodeId)}`;
	}

	function tlsHref(): string {
		return `${resolve('/tls')}?tab=dns&node=${encodeURIComponent(nodeId)}`;
	}
</script>

{#if loaded}
	<GroupedList header={m.cluster_hub_unifi_group()}>
		{#if isAdmin}
			<GroupedRow label={m.cluster_hub_unifi_binding()}>
				{#snippet trailing()}
					<select
						class="field"
						aria-label={m.cluster_hub_unifi_binding()}
						value={binding}
						disabled={busy}
						onchange={(event) => void saveBinding(event.currentTarget.value)}
					>
						<option value="">{m.settings_unifi_binding_none()}</option>
						{#each profiles as profile (profile.id)}
							<option value={profile.id}>{profile.id}</option>
						{/each}
					</select>
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow
				label={m.cluster_hub_unifi_binding()}
				detail={binding || m.settings_unifi_binding_none()}
				detailMono
			/>
		{/if}
	</GroupedList>

	<GroupedList header={m.cluster_hub_dyndns_group()}>
		{#if dyndns}
			<GroupedRow
				label={m.cluster_hub_dyndns_host()}
				detail={dyndns.hostname || m.cluster_value_unknown()}
				detailMono
			/>
			{#if isAdmin}
				<GroupedRow
					label={m.cluster_hub_dyndns_enabled()}
					detail={dyndns.enabled ? m.cluster_hub_dyndns_on() : m.cluster_hub_dyndns_off()}
				>
					{#snippet trailing()}
						{@const enabled = dyndns?.enabled === true}
						<Button disabled={busy} onclick={() => void toggleDyndns(!enabled)}>
							{enabled ? m.cluster_hub_dyndns_disable() : m.cluster_hub_dyndns_enable()}
						</Button>
					{/snippet}
				</GroupedRow>
			{:else}
				<GroupedRow
					label={m.cluster_hub_dyndns_enabled()}
					detail={dyndns.enabled ? m.cluster_hub_dyndns_on() : m.cluster_hub_dyndns_off()}
				/>
			{/if}
			{#if dyndns.public_entry}
				<GroupedRow label={m.cluster_hub_dyndns_public()} detail={m.cluster_hub_dyndns_on()} />
			{/if}
		{:else}
			<GroupedRow label={m.cluster_hub_dyndns_none()} />
		{/if}
		<div class="links">
			<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- tlsHref resolves -->
			<a class="link" href={tlsHref()}>{m.cluster_hub_open_tls()}</a>
		</div>
	</GroupedList>

	<GroupedList header={m.cluster_hub_listeners_group()}>
		{#each scopedListeners as listener (listener.id)}
			<GroupedRow
				label={listener.id}
				detail={`${listener.protocol} · ${listener.address}`}
				detailMono
			/>
		{:else}
			<GroupedRow label={m.cluster_hub_listeners_empty()} />
		{/each}
		<div class="links">
			<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- listenersHref resolves -->
			<a class="link" href={listenersHref()}>{m.cluster_hub_open_listeners()}</a>
		</div>
	</GroupedList>

	<GroupedList header={m.cluster_hub_views_group()}>
		{#each scopedViews as view (view.id)}
			<GroupedRow label={view.id} detail={view.profile || m.cluster_value_unknown()} detailMono />
		{:else}
			<GroupedRow label={m.cluster_hub_views_empty()} />
		{/each}
		<div class="links">
			<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- zonesHref resolves -->
			<a class="link" href={zonesHref()}>{m.cluster_hub_open_zones()}</a>
		</div>
	</GroupedList>
{/if}

{#if failure}
	<div class="notice">
		<ErrorNotice code={failure.code} params={failure.params} />
	</div>
{/if}

<style>
	.field {
		min-width: 8rem;
		min-height: 2.75rem;
		padding: 0.375rem 0.5rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
		font: inherit;
	}

	.links {
		padding: 0.5rem 1rem 0.75rem;
	}

	.link {
		color: var(--accent);
		text-decoration: none;
	}

	.link:hover {
		text-decoration: underline;
	}

	.notice {
		padding: 0 1rem 0.75rem;
	}
</style>
