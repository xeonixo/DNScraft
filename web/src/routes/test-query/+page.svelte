<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import DecisionSteps from '$lib/querylog/DecisionSteps.svelte';
	import FieldRow from '$lib/querylog/FieldRow.svelte';
	import Value from '$lib/querylog/Value.svelte';
	import {
		isValidClientId,
		parseTestQueryRecords,
		parseTestQuerySelection,
		runTestQuery,
		type TestQueryResult,
	} from '$lib/api/policy';
	import { domainLabel } from '$lib/policy/display';
	import { parseIp } from '$lib/policy/cidr';
	import { failureOf } from '$lib/api/result';
	import { answerLabel, dnssecLabel, selectionLabel } from '$lib/querylog/view';
	import { m } from '$lib/paraglide/messages';

	let sourceIp = $state('192.0.2.10');
	let clientId = $state('');
	let domain = $state('www.example.com');
	let qtype = $state('A');
	let protocol = $state('udp53');
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let result = $state<TestQueryResult | null>(null);

	const qtypeOptions = $derived([
		{ value: 'A', label: m.test_query_type_a() },
		{ value: 'AAAA', label: m.test_query_type_aaaa() },
		{ value: 'CNAME', label: m.test_query_type_cname() },
	]);
	const protocolOptions = $derived([
		{ value: 'udp53', label: m.test_query_protocol_udp53() },
		{ value: 'tcp53', label: m.test_query_protocol_tcp53() },
		{ value: 'doh', label: m.test_query_protocol_doh() },
		{ value: 'dot', label: m.test_query_protocol_dot() },
		{ value: 'doq', label: m.test_query_protocol_doq() },
	]);

	const answerRcode = $derived(
		result?.answer?.rcode ?? (typeof result?.rcode === 'string' ? result.rcode : null),
	);
	const records = $derived(parseTestQueryRecords(result?.answer?.records));
	const selection = $derived(parseTestQuerySelection(result?.selection));
	const filterHit = $derived.by(() => {
		const raw = result?.filter;
		if (!raw || typeof raw !== 'object') return null;
		const row = raw as Record<string, unknown>;
		return {
			rule:
				typeof row.rule_text === 'string'
					? row.rule_text
					: typeof row.rule === 'string'
						? row.rule
						: null,
			list: typeof row.list_id === 'string' ? row.list_id : null,
			mode: typeof row.block_mode === 'string' ? row.block_mode : null,
		};
	});
	const blocked = $derived(Boolean(filterHit && (filterHit.rule || filterHit.list || filterHit.mode)));

	function dash(value: unknown): string {
		if (value == null || value === '') return '—';
		return String(value);
	}

	function usLabel(value: number | undefined): string {
		if (value == null || !Number.isFinite(value)) return '—';
		if (value >= 1000) return `${(value / 1000).toFixed(value >= 10_000 ? 0 : 1)} ms`;
		return `${value} µs`;
	}

	const ipError = $derived(
		sourceIp.trim() !== '' && !parseIp(sourceIp.trim()) ? m.test_query_ip_invalid() : null,
	);
	const clientIdError = $derived(
		clientId.trim() !== '' && !isValidClientId(clientId.trim())
			? m.test_query_client_id_invalid()
			: null,
	);
	const canSubmit = $derived(!busy && !ipError && !clientIdError && domain.trim() !== '');

	async function submit(): Promise<void> {
		if (!canSubmit) return;
		busy = true;
		failure = null;
		result = null;
		try {
			result = await runTestQuery({
				domain: domain.trim(),
				qtype,
				source_ip: sourceIp.trim(),
				protocol,
				...(clientId.trim() ? { client_id: clientId.trim() } : {}),
			});
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}
</script>

<p class="lead">{m.test_query_lead()}</p>

<form class="composer" onsubmit={(event) => (event.preventDefault(), void submit())}>
	<div class="composer-grid">
		<div class="field">
			<label class="field-label" for="tq-ip">{m.test_query_source_ip()}</label>
			<input
				id="tq-ip"
				class="control mono"
				bind:value={sourceIp}
				required
				autocomplete="off"
				spellcheck="false"
				aria-invalid={ipError ? 'true' : undefined}
			/>
			{#if ipError}<p class="error-text" role="alert">{ipError}</p>{/if}
		</div>
		<div class="field">
			<label class="field-label" for="tq-client">
				{m.test_query_client_id()}
				<span class="optional">{m.test_query_client_id_optional()}</span>
			</label>
			<input
				id="tq-client"
				class="control mono"
				bind:value={clientId}
				autocomplete="off"
				spellcheck="false"
				aria-invalid={clientIdError ? 'true' : undefined}
			/>
			{#if clientIdError}<p class="error-text" role="alert">{clientIdError}</p>{/if}
		</div>
		<div class="field field-span">
			<label class="field-label" for="tq-name">{m.test_query_domain()}</label>
			<input
				id="tq-name"
				class="control mono"
				bind:value={domain}
				required
				autocomplete="off"
				spellcheck="false"
			/>
		</div>
		<div class="field field-span">
			<span class="field-label" id="tq-type-label">{m.test_query_type()}</span>
			<Segmented options={qtypeOptions} bind:value={qtype} label={m.test_query_type()} />
		</div>
		<div class="field field-span">
			<label class="field-label" for="tq-proto">{m.test_query_protocol()}</label>
			<select id="tq-proto" class="control" bind:value={protocol}>
				{#each protocolOptions as option (option.value)}
					<option value={option.value}>{option.label}</option>
				{/each}
			</select>
		</div>
	</div>
	<div class="composer-actions">
		<Button variant="primary" type="submit" disabled={!canSubmit}>{m.test_query_run()}</Button>
	</div>
</form>

{#if failure}
	<ErrorNotice code={failure.code} params={failure.params} />
{/if}

{#if result}
	<header class="result-banner" class:blocked data-testid="test-query-result">
		<span class="verdict">{blocked ? m.test_query_blocked() : m.test_query_allowed()}</span>
		{#if answerRcode}
			<span class="rcode mono">{answerRcode}</span>
		{/if}
		{#if result.view_id}
			<span class="meta mono">{result.view_id}</span>
		{/if}
	</header>

	<div class="columns">
		<div class="column">
			<GroupedList header={m.test_query_summary()}>
				{#if selection}
					<FieldRow label={m.querylog_row_selection()} value={selectionLabel(selection)} />
				{/if}
				<FieldRow label={m.querylog_row_view()} value={dash(result.view_id)} mono />
				<FieldRow label={m.querylog_row_profile()} value={dash(result.profile_id)} mono />
				{#if result.filter_set_id}
					<FieldRow label={m.querylog_row_filter_set()} value={dash(result.filter_set_id)} mono />
				{/if}
				{#if result.answer_source}
					<FieldRow
						label={m.querylog_row_answer_source()}
						value={answerLabel(String(result.answer_source))}
					/>
				{/if}
				{#if result.forward_zone}
					<FieldRow
						label={m.querylog_row_forward_zone()}
						value={dash(domainLabel(result.forward_zone))}
						mono
					/>
				{/if}
				{#if result.client_id}
					<FieldRow label={m.querylog_row_client_id()} value={dash(result.client_id)} mono />
				{/if}
				{#if result.dnssec}
					<FieldRow label={m.querylog_row_dnssec()} value={dnssecLabel(String(result.dnssec))} />
				{/if}
				{#if answerRcode}
					<FieldRow label={m.querylog_row_rcode()} value={answerRcode} mono />
				{/if}
			</GroupedList>

			{#if filterHit && (filterHit.rule || filterHit.list || filterHit.mode)}
				<GroupedList header={m.querylog_row_rule()}>
					{#if filterHit.rule}
						<FieldRow label={m.querylog_row_rule()}>
							<Value value={filterHit.rule} mono oneLine />
						</FieldRow>
					{/if}
					{#if filterHit.list}
						<FieldRow label={m.querylog_row_list()} value={filterHit.list} mono />
					{/if}
					{#if filterHit.mode}
						<FieldRow label={m.querylog_row_block_mode()} value={filterHit.mode} />
					{/if}
				</GroupedList>
			{/if}

			<GroupedList header={m.test_query_records()}>
				{#if records.length > 0}
					{#each records as rec, index (`${rec.type}:${rec.name}:${rec.data}:${index}`)}
						<div class="answer">
							<span class="type">{rec.type}</span>
							<div class="data">
								<Value value={rec.data || '—'} mono />
								{#if rec.name}
									<span class="name mono">{rec.name}</span>
								{/if}
							</div>
							<span class="ttl">{m.query_log_answer_ttl({ ttl: String(rec.ttl) })}</span>
						</div>
					{/each}
				{:else}
					<p class="empty">{m.test_query_no_records()}</p>
				{/if}
			</GroupedList>
		</div>

		<div class="column">
			<GroupedList header={m.test_query_steps()} footer={m.test_query_footnote()}>
				<DecisionSteps steps={result.steps ?? []} />
			</GroupedList>

			{#if result.timings}
				<GroupedList header={m.querylog_section_timing()}>
					<GroupedRow
						label={m.querylog_timing_select()}
						detail={usLabel(result.timings.select_us)}
						detailMono
					/>
					<GroupedRow
						label={m.querylog_timing_filter()}
						detail={usLabel(result.timings.filter_us)}
						detailMono
					/>
					<GroupedRow
						label={m.querylog_timing_resolve()}
						detail={usLabel(result.timings.resolve_us)}
						detailMono
					/>
					<GroupedRow
						label={m.querylog_timing_total()}
						detail={usLabel(result.timings.total_us)}
						detailMono
					/>
				</GroupedList>
			{/if}
		</div>
	</div>
{:else}
	<p class="footnote">{m.test_query_footnote()}</p>
{/if}

<style>
	.lead {
		margin: 0 0 1rem;
		max-width: 40rem;
		color: var(--label-2);
		line-height: 1.45;
	}

	.composer {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		margin-bottom: 1.25rem;
		padding: 1rem;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow);
	}

	.composer-grid {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: 0.75rem 1rem;
	}

	.field {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
		min-width: 0;
	}

	.field-span {
		grid-column: 1 / -1;
	}

	.field-label {
		font-size: 0.8125rem;
		font-weight: 500;
		color: var(--label-2);
	}

	.optional {
		margin-left: 0.35rem;
		font-weight: 400;
		color: var(--label-3);
	}

	.control {
		min-height: var(--control-h, 2.75rem);
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface-2);
		color: var(--label);
		font: inherit;
	}

	.control:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 1px;
	}

	.control[aria-invalid='true'] {
		border-color: var(--danger);
	}

	.mono {
		font-family: var(--font-mono);
	}

	.composer-actions {
		display: flex;
		justify-content: flex-end;
	}

	.error-text {
		margin: 0;
		font-size: 0.8125rem;
		color: var(--danger);
	}

	.result-banner {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: 0.5rem 0.875rem;
		margin: 0 0 1rem;
		padding: 0.875rem 1rem;
		border-radius: var(--r-card);
		background: var(--surface-2);
		border: 1px solid var(--separator);
	}

	.result-banner.blocked {
		border-color: var(--danger);
	}

	.result-banner.blocked .verdict {
		color: var(--danger);
	}

	.verdict {
		font-weight: 650;
		font-size: 1rem;
	}

	.rcode,
	.meta {
		font-size: 0.875rem;
		color: var(--label-2);
	}

	.columns {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: 1.25rem;
		align-items: start;
	}

	.column {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		min-width: 0;
	}

	.answer {
		display: grid;
		grid-template-columns: 3.5rem minmax(0, 1fr) auto;
		gap: 0.75rem;
		align-items: baseline;
		min-height: 2.75rem;
		padding: 0.625rem 1rem;
		color: var(--label);
	}

	.type {
		font-size: 0.75rem;
		font-weight: 600;
		letter-spacing: 0.02em;
		color: var(--label-2);
		text-transform: uppercase;
	}

	.data {
		display: flex;
		flex-direction: column;
		gap: 0.125rem;
		min-width: 0;
	}

	.name {
		font-size: 0.75rem;
		color: var(--label-3);
	}

	.ttl {
		font-size: 0.8125rem;
		color: var(--label-3);
		font-variant-numeric: tabular-nums;
	}

	.empty {
		margin: 0;
		padding: 0.75rem 1rem;
		font-size: 0.875rem;
		color: var(--label-2);
	}

	.footnote {
		margin: 0.25rem 0 0;
		font-size: 0.8125rem;
		color: var(--label-3);
		max-width: 40rem;
		line-height: 1.4;
	}

	@media (max-width: 52rem) {
		.composer-grid,
		.columns {
			grid-template-columns: 1fr;
		}
	}
</style>
