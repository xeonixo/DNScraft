<script lang="ts">
	import { onMount } from 'svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import {
		getServices,
		listFilterSets,
		putService,
		type BlockedService,
		type BlockedServicesCatalog,
		type FilterSet,
	} from '$lib/api/filtering';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { formatDateTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';
	import { displayText } from '$lib/safe-text';

	interface ServiceGroup {
		id: string;
		name: string;
		items: BlockedService[];
	}
	interface PageData {
		catalog: BlockedServicesCatalog;
		sets: FilterSet[];
	}
	type Failure = { code: string; params: Record<string, unknown> };

	const isAdmin = $derived(auth.role === 'admin');
	const locale = getLocale();

	let result = $state<Result<PageData>>({ kind: 'loading' });
	let failure = $state<Failure | null>(null);
	let toggling = $state<string | null>(null);

	const page = $derived(result.kind === 'ok' ? result.data : null);
	let query = $state('');
	const groups = $derived(page?.catalog.available ? groupServices(page.catalog.items) : []);
	/** Groups with the services whose name contains the search text (case-insensitive). */
	const shownGroups = $derived.by(() => {
		const needle = query.trim().toLowerCase();
		if (needle === '') return groups;
		return groups
			.map((group) => ({
				...group,
				items: group.items.filter((item) => (item.name || item.id).toLowerCase().includes(needle)),
			}))
			.filter((group) => group.items.length > 0);
	});
	const updated = $derived(page?.catalog.available ? updatedLine(page.catalog) : null);

	/** Keeps catalog order: first occurrence of a group_id opens the group. */
	function groupServices(items: BlockedService[]): ServiceGroup[] {
		const groups: ServiceGroup[] = [];
		const byId: Record<string, ServiceGroup> = {};
		for (const item of items) {
			const id = item.group_id || item.group || 'other';
			let group = byId[id];
			if (!group) {
				group = {
					id,
					name: item.group || item.group_id || m.blocked_services_other(),
					items: [],
				};
				byId[id] = group;
				groups.push(group);
			}
			group.items.push(item);
		}
		return groups;
	}

	function updatedLine(catalog: BlockedServicesCatalog): string | null {
		if (!catalog.catalog_updated_at) return null;
		const date = new Date(catalog.catalog_updated_at);
		if (Number.isNaN(date.getTime())) return null;
		return m.blocked_services_updated({ when: formatDateTime(date, locale) });
	}

	function patchEnabled(serviceId: string, setId: string, enabled: boolean): void {
		if (result.kind !== 'ok') return;
		const catalog = result.data.catalog;
		result = {
			kind: 'ok',
			data: {
				sets: result.data.sets,
				catalog: {
					...catalog,
					items: catalog.items.map((item) =>
						item.id === serviceId
							? { ...item, enabled: { ...item.enabled, [setId]: enabled } }
							: item,
					),
				},
			},
		};
	}

	async function load(): Promise<void> {
		failure = null;
		const catalogResult = await settle(getServices(locale));
		if (catalogResult.kind !== 'ok') {
			result = catalogResult;
			return;
		}
		if (!catalogResult.data.available) {
			result = { kind: 'ok', data: { catalog: catalogResult.data, sets: [] } };
			return;
		}
		const setsResult = await settle(listFilterSets());
		if (setsResult.kind !== 'ok') {
			result = setsResult;
			return;
		}
		result = { kind: 'ok', data: { catalog: catalogResult.data, sets: setsResult.data } };
	}

	/** Blocks or allows the service in one filter set. The switch goes back if the save fails. */
	async function toggle(
		service: BlockedService,
		set: FilterSet,
		input: HTMLInputElement,
	): Promise<void> {
		if (!isAdmin) return;
		const enabled = input.checked;
		const previous = service.enabled[set.id] === true;
		toggling = `${service.id}:${set.id}`;
		failure = null;
		patchEnabled(service.id, set.id, enabled);
		try {
			await putService(service.id, { filter_set_id: set.id, enabled });
		} catch (cause) {
			patchEnabled(service.id, set.id, previous);
			input.checked = previous;
			failure = failureOf(cause);
		} finally {
			toggling = null;
		}
	}

	onMount(() => {
		void load();
	});
</script>

<div class="blocked-services">
	<p class="lead">{m.blocked_services_lead()}</p>

	{#if result.kind === 'loading'}
		<p class="state">{m.state_loading()}</p>
	{:else if result.kind === 'unavailable'}
		<UnavailableNotice />
	{:else if result.kind === 'error'}
		<ResultNotice {result} onretry={() => void load()} />
	{:else if page && !page.catalog.available}
		<UnavailableNotice />
	{:else if page}
		{#if failure}
			<ErrorNotice code={failure.code} params={failure.params} />
		{/if}
		{#if updated}
			<p class="updated">{updated}</p>
		{/if}
		{#if page.sets.length === 0}
			<GroupedList>
				<GroupedRow label={m.blocked_services_no_sets()} />
			</GroupedList>
		{/if}
		{#if groups.length === 0}
			<GroupedList>
				<GroupedRow label={m.blocked_services_empty()} />
			</GroupedList>
		{:else}
			<input
				class="search"
				type="search"
				bind:value={query}
				aria-label={m.blocked_services_search()}
				placeholder={m.blocked_services_search()}
				autocomplete="off"
			/>
			{#if shownGroups.length === 0}
				<p class="state">{m.blocked_services_search_empty()}</p>
			{/if}
			<div class="groups">
				{#each shownGroups as group (group.id)}
					<GroupedList header={displayText(group.name).text}>
						{#each group.items as service (service.id)}
							{@const name = displayText(service.name || service.id).text}
							{#if page.sets.length === 0}
								<GroupedRow label={name} />
							{:else}
								<GroupedRow label={name}>
									{#snippet trailing()}
										<span class="toggles">
											{#each page.sets as set (set.id)}
												{@const setName = displayText(set.name || set.id).text}
												<span class="toggle">
													<span class="set-name" title={setName}>{setName}</span>
													<Switch
														checked={service.enabled[set.id] === true}
														disabled={!isAdmin || toggling === `${service.id}:${set.id}`}
														aria-label={m.blocked_services_toggle({ service: name, set: setName })}
														onchange={(event) => void toggle(service, set, event.currentTarget)}
													/>
												</span>
											{/each}
										</span>
									{/snippet}
								</GroupedRow>
							{/if}
						{/each}
					</GroupedList>
				{/each}
			</div>
		{/if}
	{/if}
</div>

<style>
	.blocked-services {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		max-width: 60rem;
	}

	.lead {
		max-width: 40rem;
		margin: 0;
		color: var(--label-2);
	}

	.state,
	.updated {
		margin: 0;
		color: var(--label-2);
	}

	.updated {
		font-size: 0.8125rem;
		color: var(--label-3);
	}

	.groups {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}

	.search {
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		font: inherit;
		box-sizing: border-box;
	}

	.toggles {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 0.375rem 1rem;
	}

	.toggle {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		min-width: 0;
	}

	.set-name {
		max-width: 12rem;
		overflow: hidden;
		font-size: 0.9375rem;
		font-weight: 500;
		color: var(--label);
		text-overflow: ellipsis;
		white-space: nowrap;
	}
</style>
