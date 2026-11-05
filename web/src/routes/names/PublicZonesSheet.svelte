<script lang="ts">
	import { resolve } from '$app/paths';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import type { DomainZone } from '$lib/api/domain-zones';
	import { displayText } from '$lib/safe-text';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		open: boolean;
		hasCloudflareToken: boolean;
		discoverReady: boolean;
		busy: boolean;
		attached: DomainZone[];
		candidates: DomainZone[];
		failure: { code: string; params: Record<string, unknown> } | null;
		onclose: () => void;
		onattach: (zone: DomainZone) => void;
		ondetach: (zone: DomainZone) => void;
	}

	let {
		open,
		hasCloudflareToken,
		discoverReady,
		busy,
		attached,
		candidates,
		failure,
		onclose,
		onattach,
		ondetach,
	}: Props = $props();
</script>

{#if open}
	<Sheet {open} title={m.names_zones_title()} {onclose} centeredOnWide>
		<p class="hint">{m.names_zones_lead()}</p>
		{#if !hasCloudflareToken}
			<p class="hint">{m.names_zones_token_missing()}</p>
			<a class="cta-link" href={resolve('/tls')}>{m.names_public_token_cta()}</a>
		{:else if !discoverReady}
			<p class="hint muted">{m.names_zones_loading()}</p>
		{:else}
			<p class="field-label">{m.names_zones_attached()}</p>
			{#if attached.length === 0}
				<p class="hint muted">{m.state_empty()}</p>
			{:else}
				<ul class="zone-list">
					{#each attached as zone (zone.name)}
						<li class="zone-row">
							<div class="zone-meta">
								<span class="mono">{displayText(zone.name, 80).text}</span>
								<span class="hint muted">
									{zone.source === 'public_domain'
										? m.names_zones_public_domain()
										: (zone.status ?? '')}
								</span>
							</div>
							{#if zone.source !== 'public_domain'}
								<Button variant="secondary" disabled={busy} onclick={() => ondetach(zone)}
									>{m.names_zones_detach()}</Button
								>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}

			<p class="field-label">{m.names_zones_discoverable()}</p>
			{#if candidates.length === 0}
				<p class="hint muted">{m.names_zones_empty_discover()}</p>
			{:else}
				<ul class="zone-list">
					{#each candidates as zone (zone.id ?? zone.name)}
						<li class="zone-row">
							<div class="zone-meta">
								<span class="mono">{displayText(zone.name, 80).text}</span>
								<span class="hint muted">{zone.status ?? ''}</span>
							</div>
							<Button variant="primary" disabled={busy} onclick={() => onattach(zone)}
								>{m.names_zones_attach()}</Button
							>
						</li>
					{/each}
				</ul>
			{/if}
		{/if}

		{#snippet footer()}
			{#if failure}
				<div class="footer-error">
					<ErrorNotice code={failure.code} params={failure.params} />
				</div>
			{/if}
			<div class="actions">
				<Button variant="secondary" onclick={onclose}>{m.action_cancel()}</Button>
			</div>
		{/snippet}
	</Sheet>
{/if}

<style>
	.hint {
		margin: 0 0 0.75rem;
		color: var(--label-2);
		font-size: 0.875rem;
	}
	.hint.muted {
		color: var(--label-3);
	}
	.field-label {
		margin: 0.75rem 0 0.375rem;
		font-size: 0.8125rem;
		font-weight: 600;
		color: var(--label-2);
	}
	.zone-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.zone-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: 0.5rem;
	}
	.zone-meta {
		display: flex;
		flex-direction: column;
		gap: 0.125rem;
		min-width: 0;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.cta-link {
		display: inline-block;
		margin-bottom: 0.75rem;
		color: var(--accent);
		font-weight: 600;
		text-decoration: none;
	}
	.cta-link:hover {
		text-decoration: underline;
	}
	.footer-error {
		margin-bottom: 0.75rem;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
	}
</style>
