<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { getConfig, ifMatchFor } from '$lib/api/config';
	import {
		getNotifications,
		putNotifications,
		testNotification,
		type NotificationChannel,
		type NotificationsData,
	} from '$lib/api/notifications';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { announce } from '$lib/live.svelte';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		isAdmin: boolean;
	}

	let { isAdmin }: Props = $props();

	interface DraftChannel {
		id: string;
		enabled: boolean;
		url: string;
		secret: string;
		clearSecret: boolean;
		hasSecret: boolean;
		hasUrl: boolean;
		events: string[];
	}

	let result = $state<Result<NotificationsData>>({ kind: 'loading' });
	let allowedHosts = $state('');
	let draft = $state<DraftChannel | null>(null);
	let editingId = $state<string | null>(null);
	let busy = $state(false);
	let testBusy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let configVersion = $state<number | null>(null);

	const channels = $derived(result.kind === 'ok' ? result.data.channels : []);
	const catalog = $derived(result.kind === 'ok' ? result.data.event_catalog : []);

	async function load(): Promise<void> {
		result = await settle(getNotifications());
		if (result.kind === 'ok') {
			allowedHosts = result.data.allowed_hosts.join('\n');
		}
		if (isAdmin) {
			try {
				const config = await getConfig();
				configVersion = config.version;
			} catch {
				configVersion = null;
			}
		}
	}

	onMount(() => {
		void load();
	});

	function openCreate(): void {
		editingId = null;
		failure = null;
		draft = {
			id: '',
			enabled: true,
			url: '',
			secret: '',
			clearSecret: false,
			hasSecret: false,
			hasUrl: false,
			events: [],
		};
	}

	function openEdit(channel: NotificationChannel): void {
		editingId = channel.id;
		failure = null;
		draft = {
			id: channel.id,
			enabled: channel.enabled,
			url: '',
			secret: '',
			clearSecret: false,
			hasSecret: channel.has_secret,
			hasUrl: Boolean(channel.host),
			events: [...channel.events],
		};
	}

	function toggleEvent(eventId: string, on: boolean): void {
		if (!draft) return;
		if (on) {
			if (!draft.events.includes(eventId)) draft.events = [...draft.events, eventId];
			return;
		}
		draft.events = draft.events.filter((id) => id !== eventId);
	}

	function channelPayload(
		channel: NotificationChannel | DraftChannel,
		isDraft: boolean,
	): {
		id: string;
		type: 'webhook';
		enabled: boolean;
		url?: string;
		secret?: string | null;
		events: string[];
	} {
		if (isDraft && draft) {
			const body: {
				id: string;
				type: 'webhook';
				enabled: boolean;
				url?: string;
				secret?: string | null;
				events: string[];
			} = {
				id: draft.id.trim(),
				type: 'webhook',
				enabled: draft.enabled,
				events: draft.events,
			};
			if (draft.url.trim() !== '') body.url = draft.url.trim();
			if (draft.clearSecret) body.secret = null;
			else if (draft.secret.trim() !== '') body.secret = draft.secret.trim();
			return body;
		}
		const existing = channel as NotificationChannel;
		return {
			id: existing.id,
			type: 'webhook',
			enabled: existing.enabled,
			events: existing.events,
		};
	}

	async function saveDraft(): Promise<void> {
		if (!draft || !isAdmin) return;
		busy = true;
		failure = null;
		try {
			const others = channels.filter((channel) => channel.id !== editingId);
			const next = [
				...others.map((channel) => channelPayload(channel, false)),
				channelPayload(draft, true),
			];
			const saved = await putNotifications(
				{
					allowed_hosts: allowedHosts
						.split(/[\n,]/)
						.map((host) => host.trim())
						.filter(Boolean),
					channels: next,
				},
				{ ifMatch: configVersion !== null ? ifMatchFor(configVersion) : undefined },
			);
			configVersion = saved.config_version;
			draft = null;
			announce(m.alerts_channels_saved());
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function removeChannel(id: string): Promise<void> {
		if (!isAdmin) return;
		busy = true;
		failure = null;
		try {
			const next = channels
				.filter((channel) => channel.id !== id)
				.map((channel) => channelPayload(channel, false));
			const saved = await putNotifications(
				{
					allowed_hosts: allowedHosts
						.split(/[\n,]/)
						.map((host) => host.trim())
						.filter(Boolean),
					channels: next,
				},
				{ ifMatch: configVersion !== null ? ifMatchFor(configVersion) : undefined },
			);
			configVersion = saved.config_version;
			announce(m.alerts_channels_saved());
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function sendTest(channelId: string): Promise<void> {
		if (!isAdmin) return;
		testBusy = true;
		failure = null;
		try {
			const result = await testNotification(channelId);
			if (result.delivered) {
				announce(m.alerts_channels_test_ok({ status: String(result.status ?? '—') }));
			} else {
				announce(m.alerts_channels_test_fail({ code: result.code ?? 'delivery' }));
			}
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			testBusy = false;
		}
	}
</script>

<section class="channels" aria-labelledby="alerts-channels-heading">
	<h2 id="alerts-channels-heading" class="section-head">{m.alerts_section_channels()}</h2>
	<p class="lead">{m.alerts_channels_lead()}</p>

	{#if result.kind === 'loading'}
		<GroupedList>
			<GroupedRow label={m.state_loading()} />
		</GroupedList>
	{:else if result.kind === 'error'}
		<ErrorNotice code={result.code} params={result.params} />
	{:else}
		{#if !isAdmin}
			<p class="note">{m.alerts_channels_viewer()}</p>
		{/if}

		{#if isAdmin}
			<label class="hosts">
				<span class="hosts-label">{m.alerts_channels_allowed_hosts()}</span>
				<textarea
					class="field"
					rows="3"
					bind:value={allowedHosts}
					spellcheck="false"
					aria-describedby="alerts-hosts-hint"
				></textarea>
				<span id="alerts-hosts-hint" class="hint">{m.alerts_channels_allowed_hosts_hint()}</span>
			</label>
		{/if}

		<GroupedList>
			{#each channels as channel (channel.id)}
				<GroupedRow
					label={channel.id}
					detail={channel.host
						? m.alerts_channels_host({ host: channel.host })
						: m.alerts_channels_url_set()}
					mono
				>
					{#snippet trailing()}
						<span class="row-actions">
							{#if isAdmin}
								<Button variant="secondary" onclick={() => openEdit(channel)}
									>{m.alerts_channels_edit()}</Button
								>
								<Button
									variant="secondary"
									disabled={testBusy}
									onclick={() => void sendTest(channel.id)}>{m.alerts_channels_test()}</Button
								>
								<Button
									variant="secondary"
									disabled={busy}
									onclick={() => void removeChannel(channel.id)}
									>{m.alerts_channels_delete()}</Button
								>
							{/if}
						</span>
					{/snippet}
				</GroupedRow>
			{:else}
				<GroupedRow label={m.alerts_channels_empty()} />
			{/each}
		</GroupedList>

		{#if isAdmin}
			<p class="actions">
				<Button variant="primary" onclick={openCreate}>{m.alerts_channels_add()}</Button>
			</p>
		{/if}
		{#if failure}<ErrorNotice code={failure.code} params={failure.params} />{/if}
	{/if}
</section>

{#if draft}
	<Sheet
		open
		title={editingId ? m.alerts_channels_edit() : m.alerts_channels_add()}
		onclose={() => {
			draft = null;
		}}
		centeredOnWide
	>
		<label class="field-block">
			<span>{m.alerts_channels_id()}</span>
			<input
				class="field"
				bind:value={draft.id}
				disabled={editingId !== null}
				autocomplete="off"
				spellcheck="false"
			/>
		</label>
		<label class="switch-row">
			<span>{m.alerts_channels_enabled()}</span>
			<Switch bind:checked={draft.enabled} aria-label={m.alerts_channels_enabled()} />
		</label>
		<label class="field-block">
			<span>{m.alerts_channels_url()}</span>
			<input
				class="field"
				type="url"
				bind:value={draft.url}
				placeholder={draft.hasUrl
					? m.alerts_channels_url_set()
					: m.alerts_channels_url_placeholder()}
				autocomplete="off"
				spellcheck="false"
			/>
		</label>
		<label class="field-block">
			<span>{m.alerts_channels_secret()}</span>
			<input
				class="field"
				type="password"
				bind:value={draft.secret}
				placeholder={draft.hasSecret ? m.alerts_channels_secret_set() : ''}
				autocomplete="new-password"
			/>
		</label>
		{#if draft.hasSecret}
			<label class="clear">
				<input type="checkbox" bind:checked={draft.clearSecret} />
				{m.alerts_channels_secret_clear()}
			</label>
		{/if}
		<p class="events-label">{m.alerts_channels_events()}</p>
		<ul class="events">
			{#each catalog as eventId (eventId)}
				<li>
					<label>
						<input
							type="checkbox"
							checked={draft.events.includes(eventId)}
							onchange={(event) =>
								toggleEvent(eventId, (event.currentTarget as HTMLInputElement).checked)}
						/>
						<code>{eventId}</code>
					</label>
				</li>
			{/each}
		</ul>
		{#snippet footer()}
			<Button variant="secondary" onclick={() => (draft = null)}>{m.action_cancel()}</Button>
			<Button
				variant="primary"
				disabled={busy || !draft || draft.id.trim() === ''}
				onclick={() => void saveDraft()}>{m.alerts_channels_save()}</Button
			>
		{/snippet}
		{#if failure}<ErrorNotice code={failure.code} params={failure.params} />{/if}
	</Sheet>
{/if}

<style>
	.channels {
		display: grid;
		gap: 0.75rem;
		margin-top: 1.5rem;
	}

	.section-head {
		margin: 0;
		font: var(--text-section);
		color: var(--label-secondary);
	}

	.lead,
	.note,
	.hint {
		margin: 0;
		font: var(--text-body);
		color: var(--label-secondary);
	}

	.hosts {
		display: grid;
		gap: 0.375rem;
	}

	.hosts-label {
		font: var(--text-body);
	}

	.field,
	textarea.field {
		width: 100%;
		padding: 0.625rem 0.75rem;
		font: var(--text-body);
		font-family: var(--font-mono);
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
		color: var(--label);
	}

	.actions {
		margin: 0;
	}

	.row-actions {
		display: inline-flex;
		flex-wrap: wrap;
		gap: 0.375rem;
	}

	.field-block,
	.switch-row {
		display: grid;
		gap: 0.375rem;
		margin-bottom: 0.75rem;
	}

	.switch-row {
		grid-template-columns: 1fr auto;
		align-items: center;
	}

	.clear {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		margin-bottom: 0.75rem;
		font: var(--text-body);
	}

	.events-label {
		margin: 0 0 0.375rem;
		font: var(--text-body);
	}

	.events {
		margin: 0 0 1rem;
		padding: 0;
		list-style: none;
		display: grid;
		gap: 0.25rem;
		max-height: 12rem;
		overflow: auto;
	}

	.events label {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		font: var(--text-caption);
	}

	.events code {
		font-family: var(--font-mono);
	}
</style>
