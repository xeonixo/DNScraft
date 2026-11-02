<script lang="ts">
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import StatTile from '$lib/components/StatTile.svelte';
	import { getDomainStats, type DomainDays, type DomainStats } from '$lib/api/stats';
	import { settle, type Result } from '$lib/api/result';
	import { shareOf } from '$lib/dashboard/view';
	import { formatDateTime, formatNumber } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { unicodeName } from '$lib/querylog/domain-display';
	import { provenanceLabel, statusStyle, type RecordStatus } from '$lib/querylog/view';
	import { displayText } from '$lib/safe-text';
	import { m } from '$lib/paraglide/messages';

	const locale = getLocale();
	const name = $derived(page.params.name ?? '');

	type DayChoice = '7' | '30';
	const dayOptions: { value: DayChoice; label: string }[] = [
		{ value: '7', label: m.domain_detail_days_7() },
		{ value: '30', label: m.domain_detail_days_30() },
	];

	let days = $state<DayChoice>('7');
	let result = $state<Result<DomainStats>>({ kind: 'loading' });
	let ticket = 0;

	const shownName = $derived(result.kind === 'ok' ? result.data.domain : name);
	const unicode = $derived(unicodeName(shownName));
	const maxDaily = $derived(
		result.kind === 'ok' ? Math.max(0, ...result.data.daily.map((row) => row.total)) : 0,
	);

	function stamp(value: string): string {
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? displayText(value).text : formatDateTime(date, locale);
	}

	/** Calendar day from the API (`YYYY-MM-DD`, UTC buckets) in the viewer's locale. */
	function formatUtcDay(day: string): string {
		const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day);
		if (!match) return displayText(day).text;
		const date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
		return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeZone: 'UTC' }).format(date);
	}

	function decisionLabel(status: string): string {
		if (
			status === 'allowed' ||
			status === 'blocked' ||
			status === 'servfail' ||
			status === 'dnssec_bogus'
		) {
			return statusStyle(status as RecordStatus).label;
		}
		return displayText(status).text;
	}

	function sourceLabel(source: string): string {
		const known = provenanceLabel(source);
		return known === source ? displayText(source).text : known;
	}

	function windowOf(choice: DayChoice): DomainDays {
		return choice === '30' ? 30 : 7;
	}

	async function load(domainName: string, choice: DayChoice): Promise<void> {
		const mine = ++ticket;
		if (domainName === '') {
			result = { kind: 'unavailable', code: 'control_api.not_found' };
			return;
		}
		result = { kind: 'loading' };
		const next = await settle(getDomainStats(domainName, windowOf(choice)));
		if (mine !== ticket) return;
		result = next;
	}

	$effect(() => {
		const domainName = name;
		const choice = days;
		void load(domainName, choice);
	});
</script>

<div class="page">
	<a class="back" href={resolve('/dashboard')}>
		<Icon name="chevron-right" size="1rem" />
		<span>{m.back_to_dashboard()}</span>
	</a>

	<header class="head">
		<h2 class="domain">{displayText(unicode).text}</h2>
		{#if unicode !== shownName}
			<p class="ascii mono">{displayText(shownName).text}</p>
		{/if}
		<Segmented options={dayOptions} bind:value={days} label={m.domain_detail_range_label()} />
	</header>

	{#if result.kind === 'loading'}
		<p class="state">{m.state_loading()}</p>
	{:else if result.kind === 'unavailable'}
		<GroupedList>
			<GroupedRow label={m.domain_detail_unseen()} detail={m.domain_detail_unseen_body()} />
		</GroupedList>
	{:else if result.kind === 'error'}
		<ErrorNotice code={result.code} params={result.params} onretry={() => void load(name, days)} />
	{:else}
		{@const stats = result.data}
		<div class="tiles">
			<StatTile label={m.dashboard_tile_total()} value={formatNumber(stats.counts.total, locale)} />
			<StatTile
				label={m.dashboard_tile_allowed()}
				value={formatNumber(stats.counts.allowed, locale)}
				tone="ok"
				toneLabel={m.querylog_status_allowed()}
			/>
			<StatTile
				label={m.dashboard_tile_blocked()}
				value={formatNumber(stats.counts.blocked, locale)}
				tone="danger"
				toneLabel={m.querylog_status_blocked()}
			/>
		</div>

		<GroupedList header={m.domain_detail_seen()} footer={m.domain_detail_retention()}>
			<GroupedRow label={m.domain_detail_first_seen()} detail={stamp(stats.first_seen)} />
			<GroupedRow label={m.domain_detail_last_seen()} detail={stamp(stats.last_seen)} />
		</GroupedList>

		<GroupedList header={m.domain_detail_clients()}>
			{#each stats.top_clients as row, index (index)}
				<GroupedRow label={displayText(row.client).text}>
					{#snippet trailing()}
						<span class="num">{formatNumber(row.queries, locale)}</span>
					{/snippet}
				</GroupedRow>
			{:else}
				<GroupedRow label={m.domain_detail_clients_empty()} />
			{/each}
		</GroupedList>

		<GroupedList header={m.domain_detail_daily()}>
			{#each stats.daily as row (row.day)}
				<GroupedRow
					label={formatUtcDay(row.day)}
					detail={m.domain_detail_daily_blocked({ count: formatNumber(row.blocked, locale) })}
					share={shareOf(row.total, maxDaily)}
				>
					{#snippet trailing()}
						<span class="num">{formatNumber(row.total, locale)}</span>
					{/snippet}
				</GroupedRow>
			{:else}
				<GroupedRow label={m.domain_detail_daily_empty()} />
			{/each}
		</GroupedList>

		{#if stats.last_decision}
			{@const decision = stats.last_decision}
			<GroupedList header={m.domain_detail_last_decision()}>
				<GroupedRow
					label={decisionLabel(decision.status)}
					detail={stamp(decision.time)}
					link={resolve('/query-log/[id]', { id: decision.id })}
				/>
				{#if decision.rule_text}
					<GroupedRow
						label={m.domain_detail_rule()}
						detail={displayText(decision.rule_text).text}
						detailMono
					/>
				{/if}
				{#if decision.source}
					<GroupedRow label={m.querylog_row_provenance()} detail={sourceLabel(decision.source)} />
				{/if}
			</GroupedList>
		{/if}
	{/if}
</div>

<style>
	.page {
		display: flex;
		flex-direction: column;
		gap: var(--gap-stack);
		min-width: 0;
	}

	.back {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		min-height: 2.75rem;
		color: var(--accent);
		text-decoration: none;
	}

	.back :global(svg) {
		transform: rotate(180deg);
	}

	.back:hover {
		text-decoration: underline;
	}

	.head {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 0.5rem;
		min-width: 0;
	}

	.domain {
		margin: 0;
		font-family: var(--font-mono);
		font-size: 1.5rem;
		font-weight: 700;
		letter-spacing: -0.02em;
		overflow-wrap: anywhere;
	}

	.ascii {
		margin: 0;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.mono {
		font-family: var(--font-mono);
		font-size: 0.875rem;
	}

	.state {
		margin: 0;
		color: var(--label-2);
	}

	.tiles {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: 0.75rem;
	}

	.num {
		font-variant-numeric: tabular-nums;
		color: var(--label-2);
	}

	@media (max-width: 40rem) {
		.tiles {
			grid-template-columns: 1fr;
		}
	}
</style>
