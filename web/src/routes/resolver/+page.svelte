<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { m } from '$lib/paraglide/messages';
	import { getConfig } from '$lib/api/config';
	import { patchConfigSection } from '$lib/settings/config-patch';

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<Record<string, unknown>>>({ kind: 'loading' });
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let expert = $state(false);

	let formCacheSizeMb = $state('64');
	let formTtlMin = $state('0');
	let formTtlMax = $state('86400');
	let formServeStale = $state('1d');
	let formPrefetch = $state(true);
	let formQueryTimeout = $state('1500ms');
	let formResolveDeadline = $state('10s');
	let formMaxReferralDepth = $state('16');
	let formMaxQueriesPerResolve = $state('64');
	let formMaxNestedDepth = $state('4');
	let formMaxCnameChain = $state('16');
	let formQnameMin = $state(true);
	let formOutgoingIpv6 = $state(true);
	let formIpv6Cooldown = $state('60s');
	let formAllowPrivateNs = $state(false);
	let formMaxConcurrent = $state('1024');
	let formRootReprime = $state('1d');
	let formNegativeTa = $state('');

	function asObject(value: unknown): Record<string, unknown> | null {
		return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null;
	}

	function strField(obj: Record<string, unknown>, key: string, fallback: string): string {
		const value = obj[key];
		if (value === undefined || value === null) return fallback;
		return String(value);
	}

	function numField(obj: Record<string, unknown>, key: string, fallback: number): string {
		const value = obj[key];
		return typeof value === 'number' && Number.isFinite(value) ? String(value) : String(fallback);
	}

	function boolField(obj: Record<string, unknown>, key: string, fallback: boolean): boolean {
		const value = obj[key];
		return typeof value === 'boolean' ? value : fallback;
	}

	function linesFromNames(raw: unknown): string {
		if (!Array.isArray(raw)) return '';
		return raw.map(String).join('\n');
	}

	function fillFromResolver(resolver: Record<string, unknown>): void {
		formCacheSizeMb = numField(resolver, 'cache_size_mb', 64);
		formTtlMin = numField(resolver, 'ttl_min', 0);
		formTtlMax = numField(resolver, 'ttl_max', 86_400);
		formServeStale = strField(resolver, 'serve_stale', '1d');
		formPrefetch = boolField(resolver, 'prefetch', true);
		formQueryTimeout = strField(resolver, 'query_timeout', '1500ms');
		formResolveDeadline = strField(resolver, 'resolve_deadline', '10s');
		formMaxReferralDepth = numField(resolver, 'max_referral_depth', 16);
		formMaxQueriesPerResolve = numField(resolver, 'max_queries_per_resolve', 64);
		formMaxNestedDepth = numField(resolver, 'max_nested_depth', 4);
		formMaxCnameChain = numField(resolver, 'max_cname_chain', 16);
		formQnameMin = boolField(resolver, 'qname_minimisation', true);
		formOutgoingIpv6 = boolField(resolver, 'outgoing_ipv6', true);
		formIpv6Cooldown = strField(resolver, 'ipv6_cooldown', '60s');
		formAllowPrivateNs = boolField(resolver, 'allow_private_nameservers', false);
		formMaxConcurrent = numField(resolver, 'max_concurrent_resolutions', 1024);
		formRootReprime = strField(resolver, 'root_reprime_interval', '1d');
		formNegativeTa = linesFromNames(resolver.negative_trust_anchors);
	}

	async function load(): Promise<void> {
		result = await settle(
			getConfig().then((snapshot) => asObject(snapshot.config?.resolver) ?? {}),
		);
		if (result.kind === 'ok') fillFromResolver(result.data);
	}

	function patchFromForm(): Record<string, unknown> {
		return {
			cache_size_mb: Number(formCacheSizeMb.trim()) || 0,
			ttl_min: Number(formTtlMin.trim()) || 0,
			ttl_max: Number(formTtlMax.trim()) || 0,
			serve_stale: formServeStale.trim() || '0s',
			prefetch: formPrefetch,
			query_timeout: formQueryTimeout.trim() || '1500ms',
			resolve_deadline: formResolveDeadline.trim() || '10s',
			max_referral_depth: Number(formMaxReferralDepth.trim()) || 0,
			max_queries_per_resolve: Number(formMaxQueriesPerResolve.trim()) || 0,
			max_nested_depth: Number(formMaxNestedDepth.trim()) || 0,
			max_cname_chain: Number(formMaxCnameChain.trim()) || 0,
			qname_minimisation: formQnameMin,
			outgoing_ipv6: formOutgoingIpv6,
			ipv6_cooldown: formIpv6Cooldown.trim() || '60s',
			allow_private_nameservers: formAllowPrivateNs,
			max_concurrent_resolutions: Number(formMaxConcurrent.trim()) || 1,
			root_reprime_interval: formRootReprime.trim() || '0s',
			negative_trust_anchors: formNegativeTa
				.split(/\n/)
				.map((line) => line.trim())
				.filter(Boolean),
		};
	}

	async function save(): Promise<void> {
		if (!isAdmin) return;
		busy = true;
		failure = null;
		try {
			await patchConfigSection('resolver', patchFromForm());
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		void load();
	});
</script>

<p class="lead">{m.resolver_lead()}</p>

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ResultNotice {result} onretry={() => void load()} />
{:else}
	{#if failure}<ErrorNotice code={failure.code} params={failure.params} />{/if}

	<div class="section-head">{m.resolver_section_cache()}</div>
	<GroupedList>
		<div class="form-grid">
			<label class="field-block" for="res-cache-mb">
				<span class="field-label">{m.resolver_cache_size_mb()}</span>
				<input
					id="res-cache-mb"
					class="field mono"
					bind:value={formCacheSizeMb}
					disabled={!isAdmin}
					inputmode="numeric"
				/>
			</label>
			<label class="field-block" for="res-ttl-min">
				<span class="field-label">{m.resolver_ttl_min()}</span>
				<input
					id="res-ttl-min"
					class="field mono"
					bind:value={formTtlMin}
					disabled={!isAdmin}
					inputmode="numeric"
				/>
			</label>
			<label class="field-block" for="res-ttl-max">
				<span class="field-label">{m.resolver_ttl_max()}</span>
				<input
					id="res-ttl-max"
					class="field mono"
					bind:value={formTtlMax}
					disabled={!isAdmin}
					inputmode="numeric"
				/>
			</label>
			<label class="field-block" for="res-serve-stale">
				<span class="field-label">{m.resolver_serve_stale()}</span>
				<input
					id="res-serve-stale"
					class="field mono"
					bind:value={formServeStale}
					disabled={!isAdmin}
				/>
			</label>
			<div class="switch-row">
				<span>{m.resolver_prefetch()}</span>
				<Switch bind:checked={formPrefetch} disabled={!isAdmin} aria-label={m.resolver_prefetch()} />
			</div>
		</div>
	</GroupedList>

	<div class="section-head">{m.resolver_section_limits()}</div>
	<GroupedList>
		<div class="form-grid">
			<label class="field-block" for="res-query-timeout">
				<span class="field-label">{m.resolver_query_timeout()}</span>
				<input
					id="res-query-timeout"
					class="field mono"
					bind:value={formQueryTimeout}
					disabled={!isAdmin}
				/>
			</label>
			<label class="field-block" for="res-deadline">
				<span class="field-label">{m.resolver_resolve_deadline()}</span>
				<input
					id="res-deadline"
					class="field mono"
					bind:value={formResolveDeadline}
					disabled={!isAdmin}
				/>
			</label>
			<label class="field-block" for="res-referral">
				<span class="field-label">{m.resolver_max_referral_depth()}</span>
				<input
					id="res-referral"
					class="field mono"
					bind:value={formMaxReferralDepth}
					disabled={!isAdmin}
					inputmode="numeric"
				/>
			</label>
			<label class="field-block" for="res-max-queries">
				<span class="field-label">{m.resolver_max_queries_per_resolve()}</span>
				<input
					id="res-max-queries"
					class="field mono"
					bind:value={formMaxQueriesPerResolve}
					disabled={!isAdmin}
					inputmode="numeric"
				/>
			</label>
			<label class="field-block" for="res-nested">
				<span class="field-label">{m.resolver_max_nested_depth()}</span>
				<input
					id="res-nested"
					class="field mono"
					bind:value={formMaxNestedDepth}
					disabled={!isAdmin}
					inputmode="numeric"
				/>
			</label>
			<label class="field-block" for="res-cname">
				<span class="field-label">{m.resolver_max_cname_chain()}</span>
				<input
					id="res-cname"
					class="field mono"
					bind:value={formMaxCnameChain}
					disabled={!isAdmin}
					inputmode="numeric"
				/>
			</label>
			<label class="field-block" for="res-concurrent">
				<span class="field-label">{m.resolver_max_concurrent_resolutions()}</span>
				<input
					id="res-concurrent"
					class="field mono"
					bind:value={formMaxConcurrent}
					disabled={!isAdmin}
					inputmode="numeric"
				/>
			</label>
			<label class="field-block" for="res-reprime">
				<span class="field-label">{m.resolver_root_reprime_interval()}</span>
				<input
					id="res-reprime"
					class="field mono"
					bind:value={formRootReprime}
					disabled={!isAdmin}
				/>
			</label>
		</div>
	</GroupedList>

	<div class="section-head">{m.resolver_section_network()}</div>
	<GroupedList>
		<div class="form-grid">
			<div class="switch-row">
				<span>{m.resolver_qname_minimisation()}</span>
				<Switch
					bind:checked={formQnameMin}
					disabled={!isAdmin}
					aria-label={m.resolver_qname_minimisation()}
				/>
			</div>
			<div class="switch-row">
				<span>{m.resolver_outgoing_ipv6()}</span>
				<Switch
					bind:checked={formOutgoingIpv6}
					disabled={!isAdmin}
					aria-label={m.resolver_outgoing_ipv6()}
				/>
			</div>
			<label class="field-block" for="res-ipv6-cooldown">
				<span class="field-label">{m.resolver_ipv6_cooldown()}</span>
				<input
					id="res-ipv6-cooldown"
					class="field mono"
					bind:value={formIpv6Cooldown}
					disabled={!isAdmin}
				/>
			</label>
			<div class="switch-row">
				<span class="switch-text"
					>{m.resolver_allow_private_nameservers()}<small
						>{m.resolver_allow_private_nameservers_hint()}</small
					></span
				>
				<Switch
					bind:checked={formAllowPrivateNs}
					disabled={!isAdmin}
					aria-label={m.resolver_allow_private_nameservers()}
				/>
			</div>
		</div>
	</GroupedList>

	<div class="section-head">{m.resolver_section_dnssec()}</div>
	<GroupedList>
		<label class="field-block area-block" for="res-nta">
			<span class="field-label">{m.resolver_negative_trust_anchors()}</span>
			<textarea
				id="res-nta"
				class="field area mono"
				rows="4"
				bind:value={formNegativeTa}
				disabled={!isAdmin}
				spellcheck="false"
			></textarea>
			<span class="hint">{m.resolver_negative_trust_anchors_hint()}</span>
		</label>
	</GroupedList>

	{#if isAdmin}
		<button type="button" class="expert-toggle" onclick={() => (expert = !expert)}>
			{expert ? m.resolver_basic_mode() : m.resolver_expert_mode()}
		</button>
		{#if expert}
			<p class="hint">{m.resolver_advanced_preserved_hint()}</p>
		{/if}
	{/if}

	{#if isAdmin}
		<div class="save-row">
			<Button variant="primary" disabled={busy} onclick={() => void save()}>{m.action_save()}</Button>
		</div>
	{/if}

	<p class="footnote">{m.resolver_footnote()}</p>
{/if}

<style>
	.lead {
		margin: 0 0 1rem;
		color: var(--label-2);
	}
	.section-head {
		margin: 1rem 0 0.5rem;
		font-size: 0.8125rem;
		font-weight: 600;
		color: var(--label-3);
		text-transform: uppercase;
	}
	.section-head:first-of-type {
		margin-top: 0;
	}
	.state {
		color: var(--label-2);
	}
	.footnote,
	.hint {
		margin-top: 0.75rem;
		font-size: 0.8125rem;
		color: var(--label-3);
	}
	.form-grid {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		padding: 0.5rem 0;
	}
	.field-block {
		display: block;
		padding: 0.375rem 1rem;
	}
	.area-block {
		padding: 0.5rem 1rem 0.75rem;
	}
	.field-label {
		display: block;
		margin-bottom: 0.25rem;
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.field {
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		font: inherit;
		box-sizing: border-box;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.area {
		min-height: 4rem;
		resize: vertical;
	}
	.switch-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		min-height: 2.75rem;
		padding: 0.375rem 1rem;
		gap: 1rem;
	}
	.switch-text {
		display: flex;
		flex-direction: column;
	}
	.switch-text small {
		font-size: 0.8125rem;
		color: var(--label-3);
	}
	.expert-toggle {
		min-height: 2.75rem;
		margin-top: 0.5rem;
		padding: 0;
		border: none;
		background: transparent;
		color: var(--accent);
		font: inherit;
		cursor: pointer;
	}
	.save-row {
		display: flex;
		justify-content: flex-end;
		margin-top: 1rem;
	}
</style>
