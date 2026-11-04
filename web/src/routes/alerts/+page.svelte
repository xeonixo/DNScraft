<script lang="ts">
	import { onMount } from 'svelte';
	import ChannelsPanel from '$lib/alerts/ChannelsPanel.svelte';
	import {
		alertCodeHint,
		alertHref,
		alertSeverityLabel,
		alertTitle,
		groupAlerts,
	} from '$lib/alerts/view';
	import { getAlerts, type AlertsData } from '$lib/api/alerts';
	import { settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import { m } from '$lib/paraglide/messages';
	import { createPoller } from '$lib/poll';

	const POLL_INTERVAL_MS = 30_000;
	const POLL_MAX_BACKOFF_MS = 300_000;

	const isAdmin = $derived(auth.role === 'admin');

	let result = $state<Result<AlertsData>>({ kind: 'loading' });

	const groups = $derived(result.kind === 'ok' ? groupAlerts(result.data.items) : []);
	const empty = $derived(result.kind === 'ok' && result.data.active_count === 0);

	async function refresh(): Promise<boolean> {
		result = await settle(getAlerts());
		return result.kind === 'ok';
	}

	const poller = createPoller(refresh, {
		intervalMs: POLL_INTERVAL_MS,
		maxBackoffMs: POLL_MAX_BACKOFF_MS,
		doc: globalThis.document,
	});

	onMount(() => {
		poller.start();
		return () => poller.stop();
	});
</script>

<div class="alerts">
	<p class="lead">{m.alerts_lead()}</p>

	{#if result.kind === 'loading'}
		<GroupedList>
			<GroupedRow label={m.state_loading()} />
		</GroupedList>
	{:else if result.kind === 'error'}
		<ErrorNotice code={result.code} params={result.params} />
	{:else if empty}
		<GroupedList>
			<GroupedRow label={m.alerts_none_title()} detail={m.alerts_empty_body()}>
				{#snippet leading()}
					<span class="symbol ok"
						><Icon name="check-circle" size="1.125rem" strokeWidth={1.7} /></span
					>
				{/snippet}
			</GroupedRow>
		</GroupedList>
	{:else}
		{#each groups as group (group.module)}
			<section class="group" aria-labelledby="alerts-{group.module}">
				<h2 id="alerts-{group.module}" class="section-head">{group.heading}</h2>
				<GroupedList>
					{#each group.items as item (item.id + JSON.stringify(item.params))}
						{@const href = alertHref(item.target_route)}
						{@const code = alertCodeHint(item)}
						<GroupedRow
							label={alertTitle(item)}
							detail={code
								? `${alertSeverityLabel(item.severity)} · ${code}`
								: alertSeverityLabel(item.severity)}
							{href}
						>
							{#snippet leading()}
								<span class="symbol {item.severity === 'critical' ? 'danger' : 'warn'}">
									<Icon name="alert-triangle" size="1.125rem" strokeWidth={1.7} />
								</span>
							{/snippet}
						</GroupedRow>
					{/each}
				</GroupedList>
			</section>
		{/each}
	{/if}

	<ChannelsPanel {isAdmin} />
</div>

<style>
	.alerts {
		display: grid;
		gap: 1rem;
		padding: 0 0 2rem;
	}

	.lead {
		margin: 0;
		font: var(--text-body);
		color: var(--label-secondary);
	}

	.section-head {
		margin: 0 0 0.5rem;
		font: var(--text-section);
		color: var(--label-secondary);
	}

	.group {
		display: grid;
		gap: 0.5rem;
	}

	.symbol {
		display: inline-flex;
		color: var(--label-secondary);
	}

	.symbol.ok {
		color: var(--ok);
	}

	.symbol.warn {
		color: var(--warn);
	}

	.symbol.danger {
		color: var(--danger);
	}
</style>
