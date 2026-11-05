<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ConfirmSheet from '$lib/components/ConfirmSheet.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import {
		getClusterSettings,
		invokeClusterNodeRpc,
		listClusterNodes,
		mintJoinToken,
		putClusterSettings,
		revokeClusterNode,
		removeClusterNode,
		updateClusterNode,
		type ClusterNode,
		type ClusterSettings,
		type ClusterTransportMode,
	} from '$lib/api/cluster';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import NodeHubPanel from '$lib/cluster/NodeHubPanel.svelte';
	import { nodeLag, nodeRoleLabel, nodeStatusLabel, nodeVerdict } from '$lib/cluster/nodes';
	import { announce } from '$lib/live.svelte';
	import { displayText } from '$lib/safe-text';
	import { formatDateTime, formatFingerprint, formatNumber } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';

	const HOST_EXAMPLE = 'ns1.dns.example.com';
	const isAdmin = $derived(auth.role === 'admin');
	const locale = getLocale();

	const nodeRows = $derived.by(() => {
		if (result.kind !== 'ok') return [];
		const lags = nodeLag(result.data);
		return result.data.map((node, index) => ({ node, lag: lags[index] ?? 0 }));
	});
	const activeCount = $derived(nodeRows.filter((row) => !row.node.revoked).length);
	const behindCount = $derived(nodeRows.filter((row) => !row.node.revoked && row.lag > 0).length);

	let result = $state<Result<ClusterNode[]>>({ kind: 'loading' });
	let joinOpen = $state(false);
	let joinNodeId = $state('');
	let joinToken = $state<string | null>(null);
	let joinExpires = $state<string | null>(null);
	let detail = $state<ClusterNode | null>(null);
	let revokeTarget = $state<ClusterNode | null>(null);
	let removeTarget = $state<ClusterNode | null>(null);
	let editTarget = $state<ClusterNode | null>(null);
	let editName = $state('');
	let editHost = $state('');
	const HOST_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;
	const hostInvalid = $derived(editHost.trim() !== '' && !HOST_RE.test(editHost.trim()));
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	let clusterSettings = $state<ClusterSettings | null>(null);
	let settingsBusy = $state(false);
	let settingsFailure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let rpcBusy = $state(false);
	let rpcResult = $state<string | null>(null);

	const transportModeOptions: { value: ClusterTransportMode; label: string }[] = [
		{ value: 'auto', label: m.cluster_settings_transport_auto() },
		{ value: 'prefer_quic', label: m.cluster_settings_transport_prefer_quic() },
		{ value: 'h2_only', label: m.cluster_settings_transport_h2_only() },
	];

	function liveTransportLabel(active: string | undefined): string {
		if (active === 'quic') return 'QUIC';
		if (active === 'h2') return 'HTTP/2';
		return m.cluster_settings_transport_live_none();
	}

	/** Software version, config version, and last contact; local has no peer contact to show. */
	function nodeMeta(node: ClusterNode): string {
		const software = node.software_version ? `v${node.software_version}` : '—';
		const version = node.applied_config_version ?? '—';
		if (!node.last_seen && (node.local === true || node.role === 'master')) {
			return m.cluster_node_meta_local({ software, version });
		}
		const seen = node.last_seen
			? formatDateTime(new Date(node.last_seen), locale)
			: m.cluster_never_seen();
		return m.cluster_node_meta({ software, version, seen });
	}

	async function load(): Promise<void> {
		result = await settle(listClusterNodes());
		if (result.kind === 'ok') {
			await loadSettings();
		}
	}

	async function loadSettings(): Promise<void> {
		try {
			clusterSettings = await getClusterSettings();
		} catch {
			clusterSettings = null;
		}
	}

	async function saveTransportMode(mode: ClusterTransportMode): Promise<void> {
		if (!isAdmin || !clusterSettings) return;
		settingsBusy = true;
		settingsFailure = null;
		const previous = clusterSettings.transport.mode;
		clusterSettings = { ...clusterSettings, transport: { ...clusterSettings.transport, mode } };
		try {
			clusterSettings = await putClusterSettings({ transport: { mode } });
			announce(m.cluster_settings_saved());
		} catch (cause) {
			clusterSettings = {
				...clusterSettings,
				transport: { ...clusterSettings.transport, mode: previous },
			};
			settingsFailure = failureOf(cause);
		} finally {
			settingsBusy = false;
		}
	}

	async function saveCompressionEnabled(enabled: boolean): Promise<void> {
		if (!isAdmin || !clusterSettings) return;
		settingsBusy = true;
		settingsFailure = null;
		const previous = clusterSettings.compression.enabled;
		clusterSettings = {
			...clusterSettings,
			compression: { ...clusterSettings.compression, enabled },
		};
		try {
			clusterSettings = await putClusterSettings({ compression: { enabled } });
			announce(m.cluster_settings_saved());
		} catch (cause) {
			clusterSettings = {
				...clusterSettings,
				compression: { ...clusterSettings.compression, enabled: previous },
			};
			settingsFailure = failureOf(cause);
		} finally {
			settingsBusy = false;
		}
	}

	async function saveReverseEnabled(enabled: boolean): Promise<void> {
		if (!isAdmin || !clusterSettings) return;
		settingsBusy = true;
		settingsFailure = null;
		const previous = clusterSettings.reverse_rpc.enabled;
		clusterSettings = {
			...clusterSettings,
			reverse_rpc: { ...clusterSettings.reverse_rpc, enabled },
		};
		try {
			clusterSettings = await putClusterSettings({ reverse_rpc: { enabled } });
			announce(m.cluster_settings_saved());
		} catch (cause) {
			clusterSettings = {
				...clusterSettings,
				reverse_rpc: { ...clusterSettings.reverse_rpc, enabled: previous },
			};
			settingsFailure = failureOf(cause);
		} finally {
			settingsBusy = false;
		}
	}

	async function runNodeStatusRpc(node: ClusterNode): Promise<void> {
		rpcBusy = true;
		rpcResult = null;
		failure = null;
		try {
			const data = await invokeClusterNodeRpc(node.node_id, { method: 'node.status' });
			rpcResult = JSON.stringify(data, null, 2);
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			rpcBusy = false;
		}
	}

	async function submitJoin(): Promise<void> {
		busy = true;
		failure = null;
		try {
			const issued = await mintJoinToken(joinNodeId.trim());
			joinToken = issued.token;
			joinExpires = issued.expires_at;
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function copyToken(): Promise<void> {
		if (!joinToken) return;
		try {
			await globalThis.navigator.clipboard.writeText(joinToken);
		} catch {
			/* denied */
		}
	}

	function openEdit(node: ClusterNode): void {
		editTarget = node;
		editName = node.display_name ?? '';
		editHost = node.hostname ?? '';
		failure = null;
	}

	async function saveEdit(): Promise<void> {
		if (!editTarget) return;
		busy = true;
		failure = null;
		try {
			await updateClusterNode(editTarget.node_id, { display_name: editName, hostname: editHost });
			editTarget = null;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function confirmRevoke(): Promise<void> {
		if (!revokeTarget) return;
		busy = true;
		failure = null;
		try {
			await revokeClusterNode(revokeTarget.node_id);
			revokeTarget = null;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function confirmRemove(): Promise<void> {
		if (!removeTarget) return;
		busy = true;
		failure = null;
		try {
			await removeClusterNode(removeTarget.node_id);
			removeTarget = null;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		void load();
	});
</script>

<p class="lead">{m.cluster_lead()}</p>

{#if failure && !editTarget && !revokeTarget}
	<div class="notice">
		<ErrorNotice code={failure.code} params={failure.params} />
	</div>
{/if}

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<GroupedList header={m.cluster_standalone_title()}>
		<GroupedRow label={m.cluster_standalone_body()} />
	</GroupedList>
{:else if result.kind === 'error'}
	<ErrorNotice code={result.code} params={result.params} />
{:else}
	{#if isAdmin}
		<div class="toolbar">
			<Button variant="primary" onclick={() => ((joinOpen = true), (joinToken = null))}>
				{m.cluster_join_token()}
			</Button>
		</div>
	{/if}

	<p class="summary">
		{m.cluster_summary({
			nodes: formatNumber(activeCount, locale),
			behind: formatNumber(behindCount, locale),
		})}
	</p>

	{#if clusterSettings}
		{@const settings = clusterSettings}
		{#if settingsFailure}
			<div class="notice">
				<ErrorNotice code={settingsFailure.code} params={settingsFailure.params} />
			</div>
		{/if}
		{#if settings.restart_required}
			<p class="restart-banner" role="status">{m.cluster_settings_restart_required()}</p>
		{/if}
		<GroupedList header={m.cluster_settings_transport_group()}>
			<GroupedRow label={m.cluster_settings_transport_mode()}>
				{#snippet trailing()}
					<Segmented
						options={transportModeOptions}
						value={settings.transport.mode}
						label={m.cluster_settings_transport_mode()}
						onchange={(mode) => {
							if (isAdmin && !settingsBusy) void saveTransportMode(mode as ClusterTransportMode);
						}}
					/>
				{/snippet}
			</GroupedRow>
			{#if settings.status?.active}
				<GroupedRow
					label={m.cluster_settings_transport_live({
						transport: liveTransportLabel(settings.status.active),
					})}
					detail={settings.status.fallback_reason
						? m.cluster_settings_transport_fallback({
								reason: settings.status.fallback_reason,
							})
						: undefined}
				/>
			{/if}
		</GroupedList>
		<GroupedList header={m.cluster_settings_compression_group()}>
			<GroupedRow
				label={m.cluster_settings_compression_enabled()}
				detail={m.cluster_settings_compression_note()}
			>
				{#snippet trailing()}
					<Switch
						checked={settings.compression.enabled}
						disabled={!isAdmin || settingsBusy}
						aria-label={m.cluster_settings_compression_enabled()}
						onchange={(event) => void saveCompressionEnabled(event.currentTarget.checked)}
					/>
				{/snippet}
			</GroupedRow>
		</GroupedList>
		<GroupedList header={m.cluster_settings_reverse_group()}>
			<GroupedRow
				label={m.cluster_settings_reverse_enabled()}
				detail={m.cluster_settings_reverse_note()}
			>
				{#snippet trailing()}
					<Switch
						checked={settings.reverse_rpc.enabled}
						disabled={!isAdmin || settingsBusy}
						aria-label={m.cluster_settings_reverse_enabled()}
						onchange={(event) => void saveReverseEnabled(event.currentTarget.checked)}
					/>
				{/snippet}
			</GroupedRow>
		</GroupedList>
	{/if}

	<GroupedList header={m.cluster_nodes_group()}>
		{#each nodeRows as { node, lag } (node.node_id)}
			<GroupedRow
				label={displayText(node.display_name || node.node_id).text}
				detail={(node.display_name
					? `${m.cluster_node_id_label({ id: displayText(node.node_id).text })} · `
					: '') +
					(node.revoked
						? `${nodeRoleLabel(node.role)} · ${m.cluster_revoked()}`
						: `${nodeRoleLabel(node.role)} · ${nodeStatusLabel(node, lag, locale)} · ${nodeMeta(node)}`)}
			>
				{#snippet leading()}
					{@const verdict = nodeVerdict(node, lag)}
					<span class="symbol {verdict.tone}">
						<Icon name={verdict.icon} size="1.125rem" strokeWidth={1.7} />
					</span>
				{/snippet}
				{#snippet trailing()}
					<Button
						onclick={() => {
							detail = node;
							rpcResult = null;
						}}>{m.cluster_detail()}</Button
					>
					{#if isAdmin && !node.revoked && node.role !== 'master' && node.local !== true}
						<Button class="quiet-danger" disabled={busy} onclick={() => (revokeTarget = node)}>
							{m.cluster_revoke()}
						</Button>
					{/if}
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.cluster_empty()} />
		{/each}
	</GroupedList>
{/if}

{#if joinOpen}
	<Sheet open={true} title={m.cluster_join_title()} onclose={() => (joinOpen = false)}>
		{#if !joinToken}
			<label class="field-label" for="join-node">{m.cluster_join_node_label()}</label>
			<input id="join-node" class="field mono" bind:value={joinNodeId} />
			{#if failure}
				<div class="notice">
					<ErrorNotice code={failure.code} params={failure.params} />
				</div>
			{/if}
			<div class="actions">
				<Button onclick={() => (joinOpen = false)}>{m.action_cancel()}</Button>
				<Button variant="primary" disabled={busy || joinNodeId.trim() === ''} onclick={submitJoin}>
					{m.cluster_join_mint()}
				</Button>
			</div>
		{:else}
			<p class="hint">{m.cluster_join_once()}</p>
			<code class="mono token">{joinToken}</code>
			{#if joinExpires}
				<p class="hint">
					{m.cluster_join_expires({ time: formatDateTime(new Date(joinExpires), locale) })}
				</p>
			{/if}
			<div class="actions">
				<Button onclick={() => void copyToken()}>{m.action_copy()}</Button>
				<Button onclick={() => (joinOpen = false)}>{m.action_close()}</Button>
			</div>
		{/if}
	</Sheet>
{/if}

{#if detail}
	{@const node = detail}
	{@const detailNodeId = node.node_id}
	{@const detailLag = nodeRows.find((row) => row.node.node_id === detailNodeId)?.lag ?? 0}
	{@const connectionLabel = node.local
		? m.cluster_connection_local()
		: node.connected
			? m.cluster_connection_connected()
			: m.cluster_connection_offline()}
	{@const transportLabel =
		node.transport === 'quic'
			? m.cluster_transport_quic()
			: node.transport === 'h2' || node.transport === 'mtls'
				? m.cluster_transport_h2()
				: m.cluster_value_unknown()}
	<Sheet open={true} title={m.cluster_detail_title()} onclose={() => (detail = null)}>
		<GroupedList>
			<GroupedRow
				label={m.cluster_field_node_id()}
				detail={displayText(node.node_id).text}
				detailMono
			/>
			<GroupedRow
				label={m.cluster_field_display_name()}
				detail={node.display_name || m.cluster_value_unknown()}
			/>
			<GroupedRow
				label={m.cluster_field_hostname()}
				detail={node.hostname || m.cluster_value_unknown()}
				detailMono
			/>
			<GroupedRow label={m.cluster_field_role()} detail={nodeRoleLabel(node.role)} />
			<GroupedRow
				label={m.cluster_field_status()}
				detail={nodeStatusLabel(node, detailLag, locale)}
			/>
			<GroupedRow label={m.cluster_field_connection()} detail={connectionLabel} />
			<GroupedRow
				label={m.cluster_field_remote_addr()}
				detail={node.remote_addr || m.cluster_value_unknown()}
				detailMono
			/>
			<GroupedRow label={m.cluster_field_transport()} detail={transportLabel} />
			<GroupedRow
				label={m.cluster_field_fingerprint()}
				detail={node.fingerprint
					? formatFingerprint(node.fingerprint)
					: m.cluster_value_unknown()}
				detailMono
			/>
			<GroupedRow
				label={m.cluster_field_joined()}
				detail={node.joined_at
					? formatDateTime(new Date(node.joined_at), locale)
					: m.cluster_value_unknown()}
				detailMono
			/>
			<GroupedRow
				label={m.cluster_field_last_seen()}
				detail={node.last_seen
					? formatDateTime(new Date(node.last_seen), locale)
					: m.cluster_never_seen()}
				detailMono
			/>
			<GroupedRow
				label={m.cluster_field_software_version()}
				detail={node.software_version ? `v${node.software_version}` : m.cluster_value_unknown()}
				detailMono
			/>
			<GroupedRow
				label={m.cluster_field_applied_version()}
				detail={String(node.applied_config_version ?? '—')}
				detailMono
			/>
		</GroupedList>
		{#if !node.revoked}
			<NodeHubPanel nodeId={detailNodeId} {isAdmin} />
		{/if}
		{#if rpcResult}
			<p class="hint">{m.cluster_rpc_status_result()}</p>
			<pre class="mono rpc-result">{rpcResult}</pre>
		{/if}
		<div class="actions">
			{#if isAdmin && node.connected && node.local !== true && node.role !== 'master'}
				<Button disabled={rpcBusy} onclick={() => void runNodeStatusRpc(node)}>
					{m.cluster_rpc_status()}
				</Button>
			{/if}
			{#if isAdmin && !node.revoked}
				<Button
					onclick={() => {
						openEdit(node);
						detail = null;
					}}>{m.cluster_edit()}</Button
				>
			{/if}
			{#if isAdmin && node.revoked && node.role !== 'master' && node.local !== true}
				<Button
					variant="danger"
					onclick={() => {
						removeTarget = node;
						detail = null;
					}}>{m.cluster_remove()}</Button
				>
			{/if}
			<Button onclick={() => (detail = null)}>{m.action_close()}</Button>
		</div>
	</Sheet>
{/if}

{#if removeTarget}
	<Sheet open={true} title={m.cluster_remove_title()} onclose={() => (removeTarget = null)}>
		<p class="hint">{m.cluster_remove_body({ id: displayText(removeTarget.node_id).text })}</p>
		<div class="actions">
			<Button onclick={() => (removeTarget = null)}>{m.action_cancel()}</Button>
			<Button variant="danger" disabled={busy} onclick={confirmRemove}>
				{m.cluster_remove()}
			</Button>
		</div>
	</Sheet>
{/if}

{#if editTarget}
	<Sheet open={true} title={m.cluster_edit_title()} onclose={() => (editTarget = null)}>
		<p class="hint">{m.cluster_edit_id({ id: displayText(editTarget.node_id).text })}</p>
		<label class="field-label" for="edit-name">{m.cluster_field_display_name()}</label>
		<input id="edit-name" class="field" maxlength="64" bind:value={editName} />
		<label class="field-label" for="edit-host">{m.cluster_field_hostname()}</label>
		<input
			id="edit-host"
			class="field mono"
			placeholder={HOST_EXAMPLE}
			autocapitalize="off"
			spellcheck="false"
			aria-invalid={hostInvalid}
			bind:value={editHost}
		/>
		<p class="hint" class:invalid={hostInvalid}>
			{hostInvalid ? m.cluster_edit_host_invalid() : m.cluster_edit_hint()}
		</p>
		{#if failure}
			<div class="notice">
				<ErrorNotice code={failure.code} params={failure.params} />
			</div>
		{/if}
		<div class="actions">
			<Button onclick={() => (editTarget = null)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy || hostInvalid} onclick={saveEdit}
				>{m.action_save()}</Button
			>
		</div>
	</Sheet>
{/if}

{#if revokeTarget}
	<ConfirmSheet
		title={m.cluster_revoke_title()}
		body={m.cluster_revoke_body({ id: displayText(revokeTarget.node_id).text })}
		confirmLabel={m.cluster_revoke_confirm()}
		{busy}
		{failure}
		onconfirm={() => void confirmRevoke()}
		oncancel={() => (revokeTarget = null)}
	/>
{/if}

<style>
	.lead {
		margin: 0 0 1rem;
		color: var(--label-2);
	}

	.toolbar {
		margin-bottom: 0.75rem;
	}

	.summary {
		margin: 0 0 0.5rem;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.symbol {
		display: inline-flex;
		flex: 0 0 auto;
	}

	.symbol.ok {
		color: var(--ok);
	}

	.symbol.warn {
		color: var(--warn);
	}

	.symbol.neutral {
		color: var(--label-3);
	}

	.state,
	.hint {
		margin: 0;
		color: var(--label-2);
		font-size: 0.84375rem;
	}

	.hint.invalid {
		color: var(--danger);
	}

	.notice {
		margin: 0.75rem 0;
	}

	.restart-banner {
		margin: 0 0 0.75rem;
		padding: 0.75rem 1rem;
		border: 1px solid var(--warn);
		border-radius: 0.5rem;
		background: color-mix(in srgb, var(--warn) 12%, transparent);
		color: var(--label-1);
		font-size: 0.875rem;
	}

	/* Revoke is a quiet destructive action: red text, no fill. The solid style lives in ConfirmSheet. */
	:global(button.btn.quiet-danger) {
		background: transparent;
		border-color: transparent;
		color: var(--danger);
	}

	.hint + .field-label {
		margin-top: 0.75rem;
	}

	.field-label {
		display: block;
		margin: 0 0 0.375rem;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.field {
		width: 100%;
		min-height: 2.75rem;
		margin-bottom: 1rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
	}

	.token {
		display: block;
		margin: 0.75rem 0;
		padding: 0.5rem;
		overflow-x: auto;
		word-break: break-all;
		background: var(--surface-2);
		border-radius: var(--r-control);
	}

	.rpc-result {
		margin: 0.5rem 0 0;
		padding: 0.5rem;
		overflow-x: auto;
		font-size: 0.75rem;
		background: var(--surface-2);
		border-radius: var(--r-control);
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
</style>
