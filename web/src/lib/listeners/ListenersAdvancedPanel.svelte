<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { getConfig } from '$lib/api/config';
	import { failureOf } from '$lib/api/result';
	import { announce } from '$lib/live.svelte';
	import { patchConfigSection } from '$lib/settings/config-patch';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		isAdmin: boolean;
	}

	let { isAdmin }: Props = $props();

	type LimitsForm = {
		udp_payload_max: number;
		query_timeout: string;
		tcp_idle_timeout: string;
		tls_handshake_timeout: string;
		max_inflight_per_listener: number;
		max_connections_per_listener: number;
		max_connections_per_source: number;
		max_quic_streams_per_connection: number;
		max_queries_per_connection: number;
		rate_per_source_ps: number;
		rate_per_source_burst: number;
		rate_per_client_id_ps: number;
		rate_per_client_id_burst: number;
	};

	type PublicForm = {
		enabled: boolean;
		ban_strikes: number;
		ban_window: string;
		ban_duration: string;
		max_tracked_sources: number;
	};

	type DdrForm = {
		enabled: boolean;
		target: string;
	};

	const DEFAULT_LIMITS: LimitsForm = {
		udp_payload_max: 1232,
		query_timeout: '5s',
		tcp_idle_timeout: '10s',
		tls_handshake_timeout: '5s',
		max_inflight_per_listener: 4096,
		max_connections_per_listener: 1024,
		max_connections_per_source: 32,
		max_quic_streams_per_connection: 64,
		max_queries_per_connection: 64,
		rate_per_source_ps: 200,
		rate_per_source_burst: 400,
		rate_per_client_id_ps: 50,
		rate_per_client_id_burst: 100,
	};

	const DEFAULT_PUBLIC: PublicForm = {
		enabled: false,
		ban_strikes: 5,
		ban_window: '60s',
		ban_duration: '15m',
		max_tracked_sources: 100_000,
	};

	const DEFAULT_DDR: DdrForm = { enabled: true, target: 'dns' };

	let limits = $state<LimitsForm>({ ...DEFAULT_LIMITS });
	let publicCfg = $state<PublicForm>({ ...DEFAULT_PUBLIC });
	let ddr = $state<DdrForm>({ ...DEFAULT_DDR });
	let loaded = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	function asRecord(value: unknown): Record<string, unknown> {
		return typeof value === 'object' && value !== null && !Array.isArray(value)
			? (value as Record<string, unknown>)
			: {};
	}

	function asNumber(value: unknown, fallback: number): number {
		return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
	}

	function asString(value: unknown, fallback: string): string {
		return typeof value === 'string' && value.trim() !== '' ? value : fallback;
	}

	function asBool(value: unknown, fallback: boolean): boolean {
		return typeof value === 'boolean' ? value : fallback;
	}

	onMount(() => {
		if (!isAdmin) return;
		void load();
	});

	async function load(): Promise<void> {
		failure = null;
		try {
			const snapshot = await getConfig();
			const section = asRecord(snapshot.config?.listeners);
			const lim = asRecord(section.limits);
			const rateSource = asRecord(lim.rate_per_source);
			const rateClient = asRecord(lim.rate_per_client_id);
			limits = {
				udp_payload_max: asNumber(lim.udp_payload_max, DEFAULT_LIMITS.udp_payload_max),
				query_timeout: asString(lim.query_timeout, DEFAULT_LIMITS.query_timeout),
				tcp_idle_timeout: asString(lim.tcp_idle_timeout, DEFAULT_LIMITS.tcp_idle_timeout),
				tls_handshake_timeout: asString(
					lim.tls_handshake_timeout,
					DEFAULT_LIMITS.tls_handshake_timeout,
				),
				max_inflight_per_listener: asNumber(
					lim.max_inflight_per_listener,
					DEFAULT_LIMITS.max_inflight_per_listener,
				),
				max_connections_per_listener: asNumber(
					lim.max_connections_per_listener,
					DEFAULT_LIMITS.max_connections_per_listener,
				),
				max_connections_per_source: asNumber(
					lim.max_connections_per_source,
					DEFAULT_LIMITS.max_connections_per_source,
				),
				max_quic_streams_per_connection: asNumber(
					lim.max_quic_streams_per_connection,
					DEFAULT_LIMITS.max_quic_streams_per_connection,
				),
				max_queries_per_connection: asNumber(
					lim.max_queries_per_connection,
					DEFAULT_LIMITS.max_queries_per_connection,
				),
				rate_per_source_ps: asNumber(rateSource.per_second, DEFAULT_LIMITS.rate_per_source_ps),
				rate_per_source_burst: asNumber(rateSource.burst, DEFAULT_LIMITS.rate_per_source_burst),
				rate_per_client_id_ps: asNumber(
					rateClient.per_second,
					DEFAULT_LIMITS.rate_per_client_id_ps,
				),
				rate_per_client_id_burst: asNumber(
					rateClient.burst,
					DEFAULT_LIMITS.rate_per_client_id_burst,
				),
			};
			const pub = asRecord(section.public);
			publicCfg = {
				enabled: asBool(pub.enabled, DEFAULT_PUBLIC.enabled),
				ban_strikes: asNumber(pub.ban_strikes, DEFAULT_PUBLIC.ban_strikes),
				ban_window: asString(pub.ban_window, DEFAULT_PUBLIC.ban_window),
				ban_duration: asString(pub.ban_duration, DEFAULT_PUBLIC.ban_duration),
				max_tracked_sources: asNumber(pub.max_tracked_sources, DEFAULT_PUBLIC.max_tracked_sources),
			};
			const ddrRaw = asRecord(section.ddr);
			ddr = {
				enabled: asBool(ddrRaw.enabled, DEFAULT_DDR.enabled),
				target: asString(ddrRaw.target, DEFAULT_DDR.target),
			};
			loaded = true;
		} catch (cause) {
			failure = failureOf(cause);
			loaded = true;
		}
	}

	async function save(): Promise<void> {
		if (!isAdmin) return;
		busy = true;
		failure = null;
		try {
			const snapshot = await getConfig();
			const section = {
				...asRecord(snapshot.config?.listeners),
			};
			await patchConfigSection('listeners', {
				...section,
				limits: {
					udp_payload_max: limits.udp_payload_max,
					query_timeout: limits.query_timeout.trim() || DEFAULT_LIMITS.query_timeout,
					tcp_idle_timeout: limits.tcp_idle_timeout.trim() || DEFAULT_LIMITS.tcp_idle_timeout,
					tls_handshake_timeout:
						limits.tls_handshake_timeout.trim() || DEFAULT_LIMITS.tls_handshake_timeout,
					max_inflight_per_listener: limits.max_inflight_per_listener,
					max_connections_per_listener: limits.max_connections_per_listener,
					max_connections_per_source: limits.max_connections_per_source,
					max_quic_streams_per_connection: limits.max_quic_streams_per_connection,
					max_queries_per_connection: limits.max_queries_per_connection,
					rate_per_source: {
						per_second: limits.rate_per_source_ps,
						burst: limits.rate_per_source_burst,
					},
					rate_per_client_id: {
						per_second: limits.rate_per_client_id_ps,
						burst: limits.rate_per_client_id_burst,
					},
				},
				public: {
					enabled: publicCfg.enabled,
					ban_strikes: publicCfg.ban_strikes,
					ban_window: publicCfg.ban_window.trim() || DEFAULT_PUBLIC.ban_window,
					ban_duration: publicCfg.ban_duration.trim() || DEFAULT_PUBLIC.ban_duration,
					max_tracked_sources: publicCfg.max_tracked_sources,
				},
				ddr: {
					enabled: ddr.enabled,
					target: ddr.target.trim() || DEFAULT_DDR.target,
				},
			});
			announce(m.listeners_advanced_saved());
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}
</script>

{#if isAdmin && loaded}
	<details class="advanced">
		<summary>{m.listeners_advanced_summary()}</summary>
		<p class="hint">{m.listeners_advanced_hint()}</p>

		<GroupedList header={m.listeners_public_group()}>
			<GroupedRow
				label={m.listeners_public_enabled()}
				detail={publicCfg.enabled ? m.listeners_public_on() : m.listeners_public_off()}
			>
				{#snippet trailing()}
					<Switch
						bind:checked={publicCfg.enabled}
						aria-label={m.listeners_public_enabled()}
					/>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.listeners_public_ban_strikes()}>
				{#snippet trailing()}
					<input class="num field" type="number" min="1" bind:value={publicCfg.ban_strikes} />
				{/snippet}
			</GroupedRow>
			<label class="field-label" for="pub-window">{m.listeners_public_ban_window()}</label>
			<input id="pub-window" class="field mono" bind:value={publicCfg.ban_window} />
			<label class="field-label" for="pub-duration">{m.listeners_public_ban_duration()}</label>
			<input id="pub-duration" class="field mono" bind:value={publicCfg.ban_duration} />
			<GroupedRow label={m.listeners_public_max_tracked()}>
				{#snippet trailing()}
					<input
						class="num field"
						type="number"
						min="1"
						bind:value={publicCfg.max_tracked_sources}
					/>
				{/snippet}
			</GroupedRow>
		</GroupedList>

		<GroupedList header={m.listeners_ddr_group()}>
			<GroupedRow
				label={m.listeners_ddr_enabled()}
				detail={ddr.enabled ? m.listeners_ddr_on() : m.listeners_ddr_off()}
			>
				{#snippet trailing()}
					<Switch bind:checked={ddr.enabled} aria-label={m.listeners_ddr_enabled()} />
				{/snippet}
			</GroupedRow>
			<label class="field-label" for="ddr-target">{m.listeners_ddr_target()}</label>
			<input id="ddr-target" class="field mono" bind:value={ddr.target} />
		</GroupedList>

		<GroupedList header={m.listeners_limits_group()}>
			<GroupedRow label={m.listeners_limits_udp_payload()}>
				{#snippet trailing()}
					<input class="num field" type="number" min="512" bind:value={limits.udp_payload_max} />
				{/snippet}
			</GroupedRow>
			<label class="field-label" for="lim-query">{m.listeners_limits_query_timeout()}</label>
			<input id="lim-query" class="field mono" bind:value={limits.query_timeout} />
			<label class="field-label" for="lim-tcp">{m.listeners_limits_tcp_idle()}</label>
			<input id="lim-tcp" class="field mono" bind:value={limits.tcp_idle_timeout} />
			<label class="field-label" for="lim-tls">{m.listeners_limits_tls_handshake()}</label>
			<input id="lim-tls" class="field mono" bind:value={limits.tls_handshake_timeout} />
			<GroupedRow label={m.listeners_limits_inflight()}>
				{#snippet trailing()}
					<input
						class="num field"
						type="number"
						min="1"
						bind:value={limits.max_inflight_per_listener}
					/>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.listeners_limits_connections()}>
				{#snippet trailing()}
					<input
						class="num field"
						type="number"
						min="1"
						bind:value={limits.max_connections_per_listener}
					/>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.listeners_limits_per_source()}>
				{#snippet trailing()}
					<input
						class="num field"
						type="number"
						min="1"
						bind:value={limits.max_connections_per_source}
					/>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.listeners_limits_quic_streams()}>
				{#snippet trailing()}
					<input
						class="num field"
						type="number"
						min="1"
						bind:value={limits.max_quic_streams_per_connection}
					/>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.listeners_limits_queries_per_conn()}>
				{#snippet trailing()}
					<input
						class="num field"
						type="number"
						min="1"
						bind:value={limits.max_queries_per_connection}
					/>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.listeners_limits_rate_source()}>
				{#snippet trailing()}
					<input class="num field" type="number" min="1" bind:value={limits.rate_per_source_ps} />
					<span class="slash">/</span>
					<input
						class="num field"
						type="number"
						min="1"
						bind:value={limits.rate_per_source_burst}
					/>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.listeners_limits_rate_client()}>
				{#snippet trailing()}
					<input
						class="num field"
						type="number"
						min="1"
						bind:value={limits.rate_per_client_id_ps}
					/>
					<span class="slash">/</span>
					<input
						class="num field"
						type="number"
						min="1"
						bind:value={limits.rate_per_client_id_burst}
					/>
				{/snippet}
			</GroupedRow>
		</GroupedList>

		{#if failure}
			<div class="notice">
				<ErrorNotice code={failure.code} params={failure.params} />
			</div>
		{/if}

		<div class="actions">
			<Button variant="primary" disabled={busy} onclick={() => void save()}>
				{m.listeners_advanced_save()}
			</Button>
		</div>
	</details>
{/if}

<style>
	.advanced {
		margin-top: 1.25rem;
	}

	.advanced summary {
		cursor: pointer;
		font-weight: 600;
		color: var(--label);
	}

	.hint {
		margin: 0.5rem 0 1rem;
		color: var(--label-2);
		font-size: 0.875rem;
	}

	.field-label {
		display: block;
		margin: 0.75rem 1rem 0.375rem;
		font-size: 0.8125rem;
		color: var(--label-2);
	}

	.field {
		display: block;
		box-sizing: border-box;
		width: calc(100% - 2rem);
		margin: 0 1rem 0.5rem;
		min-height: 2.75rem;
		padding: 0.375rem 0.5rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
		font: inherit;
	}

	.num.field {
		display: inline-block;
		width: 5.5rem;
		margin: 0;
	}

	.slash {
		margin: 0 0.25rem;
		color: var(--label-2);
	}

	.notice {
		padding: 0 1rem 0.75rem;
	}

	.actions {
		padding: 0.5rem 1rem 1rem;
	}
</style>
