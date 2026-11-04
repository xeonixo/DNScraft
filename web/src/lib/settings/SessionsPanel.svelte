<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import ConfirmSheet from '$lib/components/ConfirmSheet.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import {
		listSessions,
		revokeSession,
		type AuthSession,
		type SessionScope,
	} from '$lib/api/sessions';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { displayText } from '$lib/safe-text';
	import { formatDateTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { announce } from '$lib/live.svelte';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		isAdmin: boolean;
	}

	let { isAdmin }: Props = $props();

	const locale = getLocale();
	const scopeOptions: { value: SessionScope; label: string }[] = [
		{ value: 'own', label: m.settings_sessions_scope_own() },
		{ value: 'all', label: m.settings_sessions_scope_all() },
	];

	// Admins default to every session; viewers are always scoped to their own.
	let scope = $state<SessionScope>('all');
	let list = $state<Result<AuthSession[]>>({ kind: 'loading' });
	let hasMore = $state(false);
	let nextOffset = $state<number | null>(null);
	let revokeTarget = $state<AuthSession | null>(null);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let ticket = 0;

	const activeScope = $derived<SessionScope>(isAdmin ? scope : 'own');
	const showActor = $derived(isAdmin);

	function stamp(value: string): string {
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? displayText(value).text : formatDateTime(date, locale);
	}

	function clientLabel(session: AuthSession): string {
		const raw = session.client_label?.trim();
		return displayText(raw ? raw : m.settings_sessions_unknown_client()).text;
	}

	function roleLabel(role: string): string {
		if (role === 'admin') return m.token_scope_admin();
		if (role === 'viewer') return m.token_scope_viewer();
		return displayText(role).text;
	}

	function rowDetail(session: AuthSession): string {
		const parts: string[] = [
			m.settings_sessions_short_id({ id: displayText(session.id.slice(0, 8)).text }),
		];
		if (showActor) {
			// Federated actors are 64-char hashes; keep named accounts (break-glass) whole.
			const actor =
				session.actor_id.length > 24 ? `${session.actor_id.slice(0, 8)}…` : session.actor_id;
			parts.push(displayText(actor).text);
			if (session.role) parts.push(roleLabel(session.role));
		}
		parts.push(session.ip ? displayText(session.ip).text : '—');
		parts.push(m.settings_sessions_created({ time: stamp(session.created_at) }));
		parts.push(m.settings_sessions_seen({ time: stamp(session.last_seen) }));
		return parts.join(' · ');
	}

	async function load(reset: boolean, scopeNow: SessionScope = activeScope): Promise<void> {
		const offset = reset ? 0 : (nextOffset ?? 0);
		const mine = reset ? ++ticket : ticket;
		if (reset) {
			hasMore = false;
			list = { kind: 'loading' };
		}
		const result = await settle(listSessions(scopeNow, offset));
		if (mine !== ticket) return;
		if (result.kind === 'loading') return;
		if (result.kind !== 'ok') {
			if (reset) list = result;
			else failure = { code: result.code, params: result.kind === 'error' ? result.params : {} };
			return;
		}
		const previous = !reset && list.kind === 'ok' ? list.data : [];
		hasMore = result.data.has_more;
		nextOffset = result.data.next_offset;
		list = { kind: 'ok', data: [...previous, ...result.data.items] };
	}

	onMount(() => {
		void load(true);
	});

	function askRevoke(session: AuthSession): void {
		if (session.current) return;
		failure = null;
		revokeTarget = session;
	}

	async function confirmRevoke(): Promise<void> {
		if (!revokeTarget || revokeTarget.current) return;
		busy = true;
		failure = null;
		try {
			await revokeSession(revokeTarget.id);
			revokeTarget = null;
			announce(m.settings_sessions_revoked());
			await load(true);
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}
</script>

{#if isAdmin}
	<div class="scope">
		<Segmented
			options={scopeOptions}
			bind:value={scope}
			label={m.settings_sessions_scope_label()}
			onchange={(next) => void load(true, next)}
		/>
	</div>
{/if}

{#if list.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if list.kind === 'unavailable'}
	<UnavailableNotice />
{:else if list.kind === 'error'}
	<ErrorNotice code={list.code} params={list.params} onretry={() => void load(true)} />
{:else}
	<GroupedList header={m.settings_sessions_header()}>
		{#each list.data as session (session.id)}
			<GroupedRow label={clientLabel(session)} detail={rowDetail(session)}>
				{#snippet trailing()}
					{#if session.current}
						<span class="badge">{m.settings_sessions_current()}</span>
					{:else}
						<Button class="quiet-danger" onclick={() => askRevoke(session)}>
							{m.settings_sessions_revoke()}
						</Button>
					{/if}
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.settings_sessions_empty()} />
		{/each}
	</GroupedList>
	{#if hasMore}
		<div class="more">
			<Button disabled={busy} onclick={() => void load(false)}>{m.settings_sessions_more()}</Button>
		</div>
	{/if}
{/if}

{#if revokeTarget}
	<ConfirmSheet
		title={m.settings_sessions_revoke_title()}
		body={m.settings_sessions_revoke_body({
			client: clientLabel(revokeTarget),
			ip: displayText(revokeTarget.ip ?? '—').text,
		})}
		confirmLabel={m.settings_sessions_revoke()}
		{busy}
		{failure}
		onconfirm={() => void confirmRevoke()}
		oncancel={() => (revokeTarget = null)}
	/>
{/if}

<style>
	.scope {
		margin-bottom: 0.75rem;
	}

	.state {
		margin: 0;
		color: var(--label-2);
	}

	.badge {
		display: inline-flex;
		align-items: center;
		min-height: 1.75rem;
		padding: 0.125rem 0.625rem;
		border-radius: 999px;
		background: var(--accent-fill);
		color: var(--accent);
		font-size: 0.75rem;
		font-weight: 600;
	}

	.more {
		margin-top: 0.75rem;
	}

	/* Revoke is a quiet destructive action: red text, no fill. The solid style lives in ConfirmSheet. */
	:global(button.btn.quiet-danger) {
		background: transparent;
		border-color: transparent;
		color: var(--danger);
	}
</style>
