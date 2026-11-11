<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import {
		deleteWebBan,
		getWebAccess,
		getWebBans,
		putWebAccess,
		type WebBan,
	} from '$lib/api/system';
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

	let bans = $state<WebBan[]>([]);
	let enabled = $state(false);
	let cidrsText = $state('');
	let savedCidrs = $state<string[]>([]);
	let loaded = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	function cidrLines(text: string): string[] {
		return text
			.split('\n')
			.map((line) => line.trim())
			.filter((line) => line !== '');
	}

	function sameCidrs(left: string[], right: string[]): boolean {
		return left.length === right.length && left.every((cidr, index) => cidr === right[index]);
	}

	onMount(() => {
		if (!isAdmin) return;
		void getWebAccess()
			.then((access) => {
				enabled = access.public_enabled;
				savedCidrs = access.allowed_cidrs ?? [];
				cidrsText = savedCidrs.join('\n');
				loaded = true;
				void loadBans();
			})
			.catch((cause) => {
				failure = failureOf(cause);
			});
	});

	async function loadBans(): Promise<void> {
		try {
			bans = (await getWebBans()).items ?? [];
		} catch {
			// No ban table on this node: the list simply stays empty.
			bans = [];
		}
	}

	async function unban(ip: string): Promise<void> {
		failure = null;
		try {
			await deleteWebBan(ip);
			announce(m.settings_web_bans_lifted({ ip }));
		} catch (cause) {
			failure = failureOf(cause);
		}
		await loadBans();
	}

	async function save(nextEnabled: boolean, nextCidrs: string[]): Promise<void> {
		busy = true;
		failure = null;
		try {
			const access = await putWebAccess({
				public_enabled: nextEnabled,
				allowed_cidrs: nextCidrs,
			});
			enabled = access.public_enabled;
			savedCidrs = access.allowed_cidrs ?? nextCidrs;
			cidrsText = savedCidrs.join('\n');
			announce(enabled ? m.settings_web_access_on() : m.settings_web_access_off());
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function toggle(next: boolean): Promise<void> {
		await save(next, savedCidrs);
	}

	async function saveCidrs(): Promise<void> {
		const next = cidrLines(cidrsText);
		if (sameCidrs(next, savedCidrs)) return;
		await save(enabled, next);
	}
</script>

{#if isAdmin && (loaded || failure)}
	<GroupedList header={m.settings_group_web_access()} footer={m.settings_web_access_footer()}>
		{#if loaded}
			<GroupedRow
				label={m.settings_web_access_label()}
				detail={enabled ? m.settings_web_access_on() : m.settings_web_access_off()}
			>
				{#snippet trailing()}
					<Switch
						checked={enabled}
						disabled={busy}
						aria-label={m.settings_web_access_label()}
						onchange={(event) => void toggle(event.currentTarget.checked)}
					/>
				{/snippet}
			</GroupedRow>
			{#if enabled}
				<label class="cidrs">
					<span class="cidrs-label">{m.settings_web_access_cidrs_label()}</span>
					<textarea
						class="cidrs-input"
						rows="4"
						spellcheck="false"
						disabled={busy}
						bind:value={cidrsText}
						aria-describedby="web-access-cidrs-hint"
						onblur={() => void saveCidrs()}></textarea>
					<span id="web-access-cidrs-hint" class="cidrs-hint"
						>{m.settings_web_access_cidrs_hint()}</span
					>
				</label>
			{/if}
		{/if}
		{#if failure}
			<div class="notice">
				<ErrorNotice code={failure.code} params={failure.params} />
			</div>
		{/if}
	</GroupedList>
	{#if bans.length > 0}
		<GroupedList header={m.settings_web_bans_header()}>
			{#each bans as ban (ban.ip)}
				<GroupedRow
					label={ban.ip}
					mono
					detail={m.settings_web_bans_until({
						time: formatDateTime(new Date(ban.until), locale),
					})}
				>
					{#snippet trailing()}
						<button class="unban" type="button" onclick={() => void unban(ban.ip)}>
							{m.settings_web_bans_unban()}
						</button>
					{/snippet}
				</GroupedRow>
			{/each}
		</GroupedList>
	{/if}
	<p class="ban-link">
		<a href={resolve('/listeners')}>{m.settings_web_access_ban_link()}</a>
	</p>
{/if}

<style>
	.unban {
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

	.cidrs {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
		padding: 0 1rem 0.75rem;
	}

	.cidrs-label,
	.cidrs-hint {
		font-size: 0.8125rem;
		color: var(--label-3);
	}

	.cidrs-input {
		box-sizing: border-box;
		width: 100%;
		min-height: 5rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		color: var(--label);
		font-family: var(--font-mono);
		font-size: 0.875rem;
		resize: vertical;
	}

	.ban-link {
		margin: 0.25rem 1rem 0;
		font-size: 0.8125rem;
	}

	.ban-link a {
		color: var(--accent);
		text-decoration: none;
	}
</style>
