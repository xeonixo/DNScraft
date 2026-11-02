<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ConfirmSheet from '$lib/components/ConfirmSheet.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import { getConfig } from '$lib/api/config';
	import {
		deleteProfile,
		listProfiles,
		loadForwardZones,
		ID_PATTERN,
		parseForwardZones,
		safeSearchOf,
		saveProfile,
		withSafeSearch,
		type PolicyProfile,
	} from '$lib/api/policy';
	import { patchConfigSection } from '$lib/settings/config-patch';
	import { listFilterSets, type FilterSet } from '$lib/api/filtering';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { displayText } from '$lib/safe-text';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<PolicyProfile[]>>({ kind: 'loading' });
	let sets = $state<FilterSet[]>([]);
	let sheetOpen = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let editing = $state<PolicyProfile | null>(null);
	let expert = $state(false);
	let formId = $state('');
	let submitted = $state(false);
	let deleteTarget = $state<PolicyProfile | null>(null);
	let formFilterSet = $state('default');
	let formSafeSearch = $state(false);
	let formRebind = $state(true);
	let formAaaa = $state(false);
	let formFirefox = $state(false);
	let formIcloud = $state(false);
	let formRebindExceptions = $state('');
	let formForwardZonesAll = $state(true);
	let formForwardZoneIds = $state<string[]>([]);
	let formSchedules = $state<
		{ id: string; filter_set: string; start: string; end: string }[]
	>([]);
	let forwardZoneOptions = $state<{ id: string; zone: string }[]>([]);
	let policyBaseline = $state<Record<string, unknown>>({});
	let policyExpert = $state(false);
	let formDefaultRebind = $state(true);
	let formPtrPrefixes = $state('');
	let formLocalNxdomain = $state('');
	let formRebindCheckFz = $state('');
	let policyBusy = $state(false);
	let policyFailure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	const rows = $derived(result.kind === 'ok' ? result.data : []);

	function scheduleRowsFrom(raw: unknown): { id: string; filter_set: string; start: string; end: string }[] {
		if (!Array.isArray(raw)) return [];
		const out: { id: string; filter_set: string; start: string; end: string }[] = [];
		for (const row of raw) {
			if (!row || typeof row !== 'object') continue;
			const item = row as Record<string, unknown>;
			out.push({
				id: String(item.id ?? ''),
				filter_set: String(item.filter_set ?? 'default'),
				start: String(item.start ?? ''),
				end: String(item.end ?? ''),
			});
		}
		return out;
	}

	function schedulesToWire(
		rows: { id: string; filter_set: string; start: string; end: string }[],
	): unknown[] {
		return rows
			.filter((row) => row.id.trim() && row.filter_set.trim())
			.map((row) => ({
				id: row.id.trim(),
				filter_set: row.filter_set.trim(),
				start: row.start.trim() || '0s',
				end: row.end.trim() || '0s',
			}));
	}

	async function loadPolicyGlobals(): Promise<void> {
		if (!isAdmin) return;
		try {
			const snapshot = await getConfig();
			const policy =
				snapshot.config?.policy && typeof snapshot.config.policy === 'object'
					? ({ ...(snapshot.config.policy as Record<string, unknown>) } as Record<string, unknown>)
					: {};
			policyBaseline = policy;
			formDefaultRebind = policy.default_rebind !== false;
			formPtrPrefixes = Array.isArray(policy.ptr_prefixes)
				? policy.ptr_prefixes.map(String).join('\n')
				: '';
			formLocalNxdomain = Array.isArray(policy.local_nxdomain_suffixes)
				? policy.local_nxdomain_suffixes.map(String).join('\n')
				: '';
			formRebindCheckFz = Array.isArray(policy.rebind_check_forward_zones)
				? policy.rebind_check_forward_zones.map(String).join('\n')
				: '';
			forwardZoneOptions = parseForwardZones(snapshot.config ?? null).map((z) => ({
				id: z.id,
				zone: z.zone,
			}));
		} catch {
			policyBaseline = {};
		}
	}

	async function savePolicyGlobals(): Promise<void> {
		if (!isAdmin) return;
		policyBusy = true;
		policyFailure = null;
		const lines = (text: string): string[] =>
			text
				.split(/\n/)
				.map((line) => line.trim())
				.filter(Boolean);
		try {
			await patchConfigSection('policy', {
				...policyBaseline,
				default_rebind: formDefaultRebind,
				ptr_prefixes: lines(formPtrPrefixes),
				local_nxdomain_suffixes: lines(formLocalNxdomain),
				rebind_check_forward_zones: lines(formRebindCheckFz),
			});
			await loadPolicyGlobals();
		} catch (cause) {
			policyFailure = failureOf(cause);
		} finally {
			policyBusy = false;
		}
	}

	async function load(): Promise<void> {
		result = await settle(listProfiles());
		const setResult = await settle(listFilterSets());
		if (setResult.kind === 'ok') sets = setResult.data;
		const fz = await settle(loadForwardZones());
		if (fz.kind === 'ok') {
			forwardZoneOptions = fz.data.zones.map((z) => ({ id: z.id, zone: z.zone }));
		}
	}

	function summary(profile: PolicyProfile): string {
		const parts = [m.profiles_filter_set({ set: profile.filter_set })];
		if (safeSearchOf(profile.safesearch).enabled) parts.push(m.profiles_safesearch_on());
		if (profile.rebind === false) parts.push(m.profiles_rebind_off());
		return parts.join(' · ');
	}

	function openCreate(): void {
		editing = null;
		formId = '';
		formFilterSet = sets[0]?.id ?? 'default';
		formSafeSearch = false;
		formRebind = true;
		formAaaa = false;
		formFirefox = false;
		formIcloud = false;
		formRebindExceptions = '';
		formForwardZonesAll = true;
		formForwardZoneIds = [];
		formSchedules = [];
		failure = null;
		submitted = false;
		sheetOpen = true;
	}

	function openEdit(profile: PolicyProfile): void {
		editing = profile;
		formId = profile.id;
		formFilterSet = profile.filter_set;
		formSafeSearch = safeSearchOf(profile.safesearch).enabled;
		formRebind = profile.rebind !== false;
		formAaaa = profile.suppress_aaaa;
		formFirefox = profile.firefox_canary;
		formIcloud = profile.icloud_private_relay;
		formRebindExceptions = (profile.rebind_exceptions ?? []).join('\n');
		formForwardZonesAll = profile.forward_zones === null;
		formForwardZoneIds = profile.forward_zones ? [...profile.forward_zones] : [];
		formSchedules = scheduleRowsFrom(profile.schedules);
		failure = null;
		submitted = false;
		sheetOpen = true;
	}

	function toggleForwardZoneId(id: string, on: boolean): void {
		if (on) {
			if (!formForwardZoneIds.includes(id)) formForwardZoneIds = [...formForwardZoneIds, id];
		} else {
			formForwardZoneIds = formForwardZoneIds.filter((zid) => zid !== id);
		}
	}

	function addScheduleRow(): void {
		formSchedules = [
			...formSchedules,
			{ id: '', filter_set: formFilterSet, start: '0s', end: '0s' },
		];
	}

	function bodyFromForm(): Omit<PolicyProfile, 'id'> {
		const rebind_exceptions = formRebindExceptions
			.split(/\n/)
			.map((line) => line.trim())
			.filter(Boolean);
		const forward_zones = formForwardZonesAll
			? null
			: formForwardZoneIds.length > 0
				? [...formForwardZoneIds]
				: [];
		return {
			filter_set: formFilterSet,
			suppress_aaaa: formAaaa,
			firefox_canary: formFirefox,
			icloud_private_relay: formIcloud,
			rebind: formRebind ? true : false,
			rebind_exceptions,
			forward_zones,
			safesearch: withSafeSearch(editing?.safesearch, formSafeSearch),
			schedules: schedulesToWire(formSchedules),
		};
	}

	const idError = $derived.by(() => {
		if (editing) return null;
		const id = formId.trim();
		if (id === '') return submitted ? m.field_id_required() : null;
		return ID_PATTERN.test(id) ? null : m.field_id_invalid();
	});

	async function submit(): Promise<void> {
		submitted = true;
		if (!editing && !ID_PATTERN.test(formId.trim())) return;
		failure = null;
		busy = true;
		const id = editing?.id ?? formId.trim();
		try {
			await saveProfile(id, bodyFromForm());
			sheetOpen = false;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function removeProfile(id: string): Promise<void> {
		busy = true;
		failure = null;
		try {
			await deleteProfile(id);
			deleteTarget = null;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		void load();
		void loadPolicyGlobals();
	});
</script>

<p class="lead">{m.profiles_lead()}</p>

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ResultNotice {result} onretry={() => void load()} />
{:else}
	{#if failure && !sheetOpen && !deleteTarget}<ErrorNotice
			code={failure.code}
			params={failure.params}
		/>{/if}
	<GroupedList>
		{#each rows as profile (profile.id)}
			<GroupedRow label={profile.id} detail={summary(profile)}>
				{#snippet trailing()}
					{#if isAdmin}
						<div class="actions">
							<Button onclick={() => openEdit(profile)}>{m.action_edit()}</Button>
							<Button variant="danger" disabled={busy} onclick={() => (deleteTarget = profile)}>
								{m.action_delete()}
							</Button>
						</div>
					{/if}
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.state_empty()} />
		{/each}
		{#if isAdmin}
			<button type="button" class="add-row" onclick={openCreate}>{m.profiles_add()}</button>
		{/if}
	</GroupedList>
	{#if isAdmin}
		<button type="button" class="expert-toggle page-expert" onclick={() => (policyExpert = !policyExpert)}>
			{policyExpert ? m.profiles_policy_basic() : m.profiles_policy_advanced()}
		</button>
		{#if policyExpert}
			{#if policyFailure}<ErrorNotice code={policyFailure.code} params={policyFailure.params} />{/if}
			<GroupedList header={m.profiles_policy_globals_section()}>
				<div class="policy-form">
					<div class="switch-row">
						<span class="switch-text"
							>{m.profiles_default_rebind_label()}<small>{m.profiles_default_rebind_hint()}</small
							></span
						>
						<Switch bind:checked={formDefaultRebind} aria-label={m.profiles_default_rebind_label()} />
					</div>
					<label class="field-block" for="policy-ptr">
						<span class="field-label">{m.profiles_ptr_prefixes_label()}</span>
						<textarea
							id="policy-ptr"
							class="field area mono"
							rows="2"
							bind:value={formPtrPrefixes}
							spellcheck="false"
						></textarea>
					</label>
					<label class="field-block" for="policy-nxdomain">
						<span class="field-label">{m.profiles_local_nxdomain_label()}</span>
						<textarea
							id="policy-nxdomain"
							class="field area mono"
							rows="2"
							bind:value={formLocalNxdomain}
							spellcheck="false"
						></textarea>
					</label>
					<label class="field-block" for="policy-rebind-fz">
						<span class="field-label">{m.profiles_rebind_check_fz_label()}</span>
						<textarea
							id="policy-rebind-fz"
							class="field area mono"
							rows="2"
							bind:value={formRebindCheckFz}
							spellcheck="false"
						></textarea>
						<span class="hint">{m.profiles_rebind_check_fz_hint()}</span>
					</label>
					<div class="sheet-actions">
						<Button variant="primary" disabled={policyBusy} onclick={() => void savePolicyGlobals()}>
							{m.action_save()}
						</Button>
					</div>
				</div>
			</GroupedList>
		{/if}
	{/if}
	<p class="footnote">{m.profiles_footnote()}</p>
{/if}

{#if deleteTarget && isAdmin}
	<ConfirmSheet
		title={m.profiles_delete_title()}
		body={m.profiles_delete_body({ id: displayText(deleteTarget.id).text })}
		{busy}
		{failure}
		oncancel={() => (deleteTarget = null)}
		onconfirm={() => void removeProfile(deleteTarget?.id ?? '')}
	/>
{/if}

{#if sheetOpen && isAdmin}
	<Sheet
		open={sheetOpen}
		title={editing ? m.profiles_edit_title() : m.profiles_add_title()}
		onclose={() => (sheetOpen = false)}
	>
		{#if !editing}
			<label class="field-label" for="profile-id">{m.profiles_id_label()}</label>
			<input
				id="profile-id"
				class="field"
				bind:value={formId}
				autocomplete="off"
				aria-invalid={idError ? 'true' : undefined}
				aria-describedby={idError ? 'profile-id-error' : undefined}
			/>
			{#if idError}<p id="profile-id-error" class="error-text" role="alert">{idError}</p>{/if}
		{/if}
		<label class="field-label" for="profile-set">{m.profiles_filter_set_label()}</label>
		<select id="profile-set" class="field" bind:value={formFilterSet}>
			{#each sets as set (set.id)}
				<option value={set.id}>{set.name || set.id}</option>
			{/each}
		</select>
		<div class="switch-row">
			<span class="switch-text"
				>{m.profiles_safesearch_label()}<small>{m.profiles_safesearch_hint()}</small></span
			>
			<Switch bind:checked={formSafeSearch} aria-label={m.profiles_safesearch_label()} />
		</div>
		<div class="switch-row">
			<span class="switch-text"
				>{m.profiles_rebind_label()}<small>{m.profiles_rebind_hint()}</small></span
			>
			<Switch bind:checked={formRebind} aria-label={m.profiles_rebind_label()} />
		</div>
		<button type="button" class="expert-toggle" onclick={() => (expert = !expert)}>
			{expert ? m.profiles_basic_mode() : m.profiles_expert_mode()}
		</button>
		{#if expert}
			<div class="switch-row">
				<span class="switch-text"
					>{m.profiles_aaaa_label()}<small>{m.profiles_aaaa_hint()}</small></span
				>
				<Switch bind:checked={formAaaa} aria-label={m.profiles_aaaa_label()} />
			</div>
			<div class="switch-row">
				<span class="switch-text"
					>{m.profiles_firefox_label()}<small>{m.profiles_firefox_hint()}</small></span
				>
				<Switch bind:checked={formFirefox} aria-label={m.profiles_firefox_label()} />
			</div>
			<div class="switch-row">
				<span class="switch-text"
					>{m.profiles_icloud_label()}<small>{m.profiles_icloud_hint()}</small></span
				>
				<Switch bind:checked={formIcloud} aria-label={m.profiles_icloud_label()} />
			</div>
			<label class="field-label" for="profile-rebind-ex">{m.profiles_rebind_exceptions_label()}</label>
			<textarea
				id="profile-rebind-ex"
				class="field area mono"
				rows="2"
				bind:value={formRebindExceptions}
				spellcheck="false"
			></textarea>
			<p class="hint">{m.profiles_rebind_exceptions_hint()}</p>
			<p class="field-label">{m.profiles_forward_zones_label()}</p>
			<label class="entry-pick">
				<input type="checkbox" bind:checked={formForwardZonesAll} />
				<span>{m.profiles_forward_zones_all()}</span>
			</label>
			{#if !formForwardZonesAll}
				{#if forwardZoneOptions.length === 0}
					<p class="hint">{m.profiles_forward_zones_empty()}</p>
				{:else}
					<ul class="fz-picks">
						{#each forwardZoneOptions as zone (zone.id)}
							<li>
								<label class="entry-pick">
									<input
										type="checkbox"
										checked={formForwardZoneIds.includes(zone.id)}
										onchange={(event) =>
											toggleForwardZoneId(
												zone.id,
												(event.currentTarget as HTMLInputElement).checked,
											)}
									/>
									<span class="mono">{zone.id}</span>
									<span class="muted">{zone.zone}</span>
								</label>
							</li>
						{/each}
					</ul>
				{/if}
			{/if}
			<p class="field-label">{m.profiles_schedules_label()}</p>
			<p class="hint">{m.profiles_schedules_hint()}</p>
			{#each formSchedules as row, index (index)}
				<div class="schedule-row">
					<input
						class="field"
						placeholder={m.profiles_schedule_id_placeholder()}
						bind:value={row.id}
						autocomplete="off"
					/>
					<select class="field" bind:value={row.filter_set}>
						{#each sets as set (set.id)}
							<option value={set.id}>{set.name || set.id}</option>
						{/each}
					</select>
					<input class="field mono" placeholder={m.profiles_schedule_start()} bind:value={row.start} />
					<input class="field mono" placeholder={m.profiles_schedule_end()} bind:value={row.end} />
					<Button
						variant="secondary"
						onclick={() => {
							formSchedules = formSchedules.filter((_, i) => i !== index);
						}}>{m.action_delete()}</Button
					>
				</div>
			{/each}
			<Button variant="secondary" onclick={addScheduleRow}>{m.profiles_schedules_add()}</Button>
		{/if}
		{#if failure}<ErrorNotice code={failure.code} params={failure.params} />{/if}
		<div class="sheet-actions">
			<Button variant="secondary" onclick={() => (sheetOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy} onclick={() => void submit()}
				>{m.action_save()}</Button
			>
		</div>
	</Sheet>
{/if}

<style>
	.lead {
		margin: 0 0 1rem;
		color: var(--label-2);
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
	.add-row {
		display: flex;
		min-height: 2.75rem;
		width: 100%;
		padding: 0.75rem 1rem;
		border: none;
		border-top: 1px solid var(--separator);
		background: transparent;
		color: var(--accent);
		font: inherit;
		font-weight: 500;
		cursor: pointer;
	}
	.error-text {
		margin: 0.25rem 0 0;
		font-size: 0.8125rem;
		color: var(--danger);
	}
	.actions {
		display: flex;
		gap: 0.375rem;
	}
	.field-label {
		display: block;
		margin: 0.75rem 0 0.25rem;
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
	}
	.switch-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		min-height: 2.75rem;
	}
	.switch-text {
		display: flex;
		flex-direction: column;
		padding: 0.5rem 1rem 0.5rem 0;
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
	.page-expert {
		margin-top: 1rem;
	}
	.policy-form {
		padding: 0.25rem 0;
	}
	.field-block {
		display: block;
		padding: 0.375rem 1rem;
	}
	.entry-pick {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		margin: 0.25rem 0;
		font-size: 0.8125rem;
		cursor: pointer;
	}
	.fz-picks {
		margin: 0.25rem 0 0.75rem;
		padding: 0;
		list-style: none;
	}
	.fz-picks .muted {
		color: var(--label-3);
	}
	.schedule-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.375rem;
		margin-bottom: 0.5rem;
	}
	.schedule-row .field {
		min-height: 2.25rem;
	}
	.area {
		min-height: 3rem;
		resize: vertical;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.sheet-actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
</style>
