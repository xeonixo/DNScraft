<script lang="ts">
	import { resolve } from '$app/paths';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import StatusMark from './StatusMark.svelte';
	import Value from './Value.svelte';
	import { answersOf, trackerOf, type QueryRecord } from '$lib/api/query-log';
	import { unicodeName } from './domain-display';
	import { displayText, neutralize } from '$lib/safe-text';
	import { formatDateTime, formatMilliseconds, formatTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { answerSummary, microsToMilliseconds, statusOf, statusStyle } from './view';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		rows: QueryRecord[];
		/** Adds the answer code and latency to the meta line. */
		technical?: boolean;
	}

	let { rows, technical = false }: Props = $props();
	const locale = getLocale();
</script>

<GroupedList>
	{#each rows as record (record.id)}
		{@const style = statusStyle(statusOf(record))}
		{@const unicode = unicodeName(record.query.name)}
		{@const answers = technical ? answerSummary(answersOf(record)) : ''}
		{@const tracker = trackerOf(record.tracker)}
		{@const client = displayText(
			record.client?.display_name ?? record.client_id ?? record.source_ip,
			32,
		).text}
		<a class="card" href={resolve('/query-log/[id]', { id: record.id })}>
			<StatusMark icon={style.icon} tone={style.tone} label={style.label} compact />
			<span class="body">
				<span class="domain mono"><Value value={unicode} mono /></span>
				<span class="meta">
					<span class="client">{client}</span>
					<span class="mono"
						>{record.query.type} · {record.protocol}{#if record.node_id}
							· {record.node_id}{/if}{#if technical}
							· {record.rcode} · {formatMilliseconds(
								microsToMilliseconds(record.timings.total_us),
								locale,
							)}{/if}</span
					>
					{#if tracker}
						<span class="tracker">{displayText(tracker.name, 24).text}</span>
					{/if}
					{#if answers !== ''}
						<span class="answers mono">{displayText(answers, 48).text}</span>
					{/if}
				</span>
			</span>
			<time
				class="time mono"
				datetime={record.time}
				title={formatDateTime(new Date(record.time), locale)}
				>{formatTime(new Date(record.time), locale)}</time
			>
			<span class="chev" aria-hidden="true"><Icon name="chevron-right" size="1rem" /></span>
			<span class="sr-only">{m.querylog_open_row({ domain: neutralize(unicode) })}</span>
		</a>
	{/each}
</GroupedList>

<style>
	.card {
		position: relative;
		display: grid;
		grid-template-columns: 1.25rem minmax(0, 1fr) auto;
		align-items: start;
		gap: 0.125rem 0.625rem;
		min-height: 2.5rem;
		padding: 0.4375rem 2rem 0.4375rem 0.75rem;
		color: var(--label);
		text-decoration: none;
	}

	.card:hover {
		background: var(--surface-2);
	}

	.card :global(.mark) {
		margin-top: 0.125rem;
	}

	.body {
		display: grid;
		gap: 0.0625rem;
		min-width: 0;
	}

	.domain {
		min-width: 0;
		font-size: 0.875rem;
		overflow-wrap: anywhere;
	}

	.meta {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: 0.125rem 0.5rem;
		min-width: 0;
		font-size: 0.75rem;
		color: var(--label-2);
	}

	.client {
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 12rem;
	}

	.tracker {
		font-weight: 600;
		color: var(--label);
	}

	.answers {
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 100%;
	}

	.time {
		margin-top: 0.125rem;
		font-size: 0.75rem;
		color: var(--label-2);
		white-space: nowrap;
		font-variant-numeric: tabular-nums;
	}

	.mono {
		font-family: var(--font-mono);
	}

	.chev {
		position: absolute;
		inset-inline-end: 0.625rem;
		top: 50%;
		transform: translateY(-50%);
		color: var(--label-3);
	}
</style>
