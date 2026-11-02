<script lang="ts">
	import { onMount } from 'svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { getConfig, ifMatchFor } from '$lib/api/config';
	import { getBackups, putBackupSettings, type BackupStatus } from '$lib/api/system';
	import { formatDateTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { failureOf } from '$lib/api/result';
	import { announce } from '$lib/live.svelte';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		isAdmin: boolean;
	}

	let { isAdmin }: Props = $props();

	const locale = getLocale();

	let status = $state<BackupStatus | null>(null);
	let configVersion = $state<number | null>(null);
	let retention = $state(7);
	let loaded = $state(false);
	let unavailable = $state(false);
	let busy = $state(false);
	let retentionBusy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	onMount(() => {
		if (!isAdmin) return;
		void load();
	});

	async function load(): Promise<void> {
		failure = null;
		unavailable = false;
		try {
			const [backups, snapshot] = await Promise.all([getBackups(), getConfig()]);
			status = backups;
			retention = backups.retention_count;
			configVersion = snapshot.version;
			loaded = true;
		} catch (cause) {
			const err = failureOf(cause);
			if (err.code === 'control_api.not_found' || cause instanceof Error === false) {
				unavailable = true;
			}
			// 404 from getBackups means this node has no backup directory.
			if (
				typeof cause === 'object' &&
				cause !== null &&
				'status' in cause &&
				(cause as { status: number }).status === 404
			) {
				unavailable = true;
				loaded = true;
				return;
			}
			failure = err;
			loaded = true;
		}
	}

	function lastRunLabel(run: BackupStatus['last_run']): string {
		if (!run || typeof run !== 'object') return m.config_backups_never();
		const at = run.at;
		const when =
			typeof at === 'number'
				? formatDateTime(new Date(at * 1000), locale)
				: typeof at === 'string'
					? formatDateTime(new Date(at), locale)
					: m.config_backups_never();
		if (run.result === 'error') {
			return m.config_backups_last_error({
				time: when,
				code: typeof run.code === 'string' ? run.code : '—',
			});
		}
		return m.config_backups_last_ok({ time: when });
	}

	async function toggle(next: boolean): Promise<void> {
		if (!status) return;
		busy = true;
		failure = null;
		try {
			const result = await putBackupSettings(
				{ enabled: next, retention_count: retention },
				{ ifMatch: ifMatchFor(configVersion) },
			);
			configVersion = result.version;
			status = { ...status, enabled: result.enabled, retention_count: result.retention_count };
			announce(next ? m.config_backups_on() : m.config_backups_off());
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function saveRetention(): Promise<void> {
		if (!status) return;
		retentionBusy = true;
		failure = null;
		try {
			const result = await putBackupSettings(
				{ enabled: status.enabled, retention_count: retention },
				{ ifMatch: ifMatchFor(configVersion) },
			);
			configVersion = result.version;
			status = { ...status, enabled: result.enabled, retention_count: result.retention_count };
			announce(m.config_backups_saved());
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			retentionBusy = false;
		}
	}
</script>

{#if isAdmin && loaded}
	<GroupedList header={m.config_section_backups()} footer={m.config_backups_detail()}>
		{#if unavailable}
			<GroupedRow label={m.config_backups_label()} detail={m.config_backups_unavailable()} />
		{:else if status}
			{@const backups = status}
			<GroupedRow
				label={m.config_backups_label()}
				detail={backups.enabled ? m.config_backups_on() : m.config_backups_off()}
			>
				{#snippet trailing()}
					<Switch
						checked={backups.enabled}
						disabled={busy}
						aria-label={m.config_backups_label()}
						onchange={(event) => void toggle(event.currentTarget.checked)}
					/>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.config_backups_retention()}>
				{#snippet trailing()}
					<input
						class="retention field"
						type="number"
						min="1"
						max="365"
						bind:value={retention}
						aria-label={m.config_backups_retention()}
					/>
					<button
						class="save-link"
						type="button"
						disabled={retentionBusy}
						onclick={() => void saveRetention()}
					>
						{m.config_backups_save_retention()}
					</button>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.config_backups_directory()} detail={backups.directory} detailMono />
			<GroupedRow
				label={m.config_backups_files()}
				detail={String(backups.files)}
				detailMono
			/>
			<GroupedRow label={m.config_backups_last_run()} detail={lastRunLabel(backups.last_run)} />
			{#if backups.next_run}
				<GroupedRow
					label={m.config_backups_next_run()}
					detail={formatDateTime(new Date(backups.next_run), locale)}
					detailMono
				/>
			{/if}
		{/if}
		{#if failure}
			<div class="notice">
				<ErrorNotice code={failure.code} params={failure.params} />
			</div>
		{/if}
	</GroupedList>
{/if}

<style>
	.retention.field {
		width: 5rem;
		min-height: 2.75rem;
		padding: 0.375rem 0.5rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
	}

	.save-link {
		min-height: 2.75rem;
		padding: 0 0.75rem;
		border: none;
		background: transparent;
		color: var(--accent);
		font: inherit;
		cursor: pointer;
	}

	.notice {
		padding: 0 1rem 0.75rem;
	}
</style>
