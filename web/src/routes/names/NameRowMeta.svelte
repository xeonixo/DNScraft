<script lang="ts">
	import type { PolicyRecord } from '$lib/api/policy';
	import { resolveAnswersForRecord } from '$lib/names/resolve-answers';
	import { displayText } from '$lib/safe-text';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		local: PolicyRecord;
		viewIds: string[];
		showPublicBadge?: boolean;
	}

	let { local, viewIds, showPublicBadge = false }: Props = $props();

	const overrideCount = $derived(Object.keys(local.overrides ?? {}).length);
	const answers = $derived(
		resolveAnswersForRecord(local, viewIds).filter((answer) => answer.deviant),
	);
</script>

<span class="meta">
	{m.names_ttl_short({ ttl: String(local.ttl) })}{#if showPublicBadge}
		· {m.names_public_badge()}{/if}{#if overrideCount > 0}
		· {overrideCount === 1
			? m.names_overrides_badge_one({ count: '1' })
			: m.names_overrides_badge_other({ count: String(overrideCount) })}{/if}
	{#if local.comment}
		· <span class="comment" title={local.comment}>{displayText(local.comment, 40).text}</span>{/if}
	{#if (local.tags ?? []).length > 0}
		· {#each local.tags ?? [] as tag (tag)}<span class="tag-pill">{tag}</span>{/each}{/if}
	{#each answers as answer (answer.view)}
		<span class="answer-chip mono">{answer.view} → {answer.label}</span>
	{/each}
</span>

<style>
	.meta {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: flex-end;
		max-width: 18rem;
		gap: 0.25rem 0.35rem;
		color: var(--label-3);
		font-size: 0.75rem;
	}
	.comment {
		color: var(--label-2);
	}
	.tag-pill {
		display: inline-block;
		padding: 0.05rem 0.35rem;
		border-radius: 0.25rem;
		background: color-mix(in srgb, var(--label) 12%, transparent);
		font-size: 0.75rem;
		color: var(--label-2);
	}
	.answer-chip {
		display: inline-block;
		padding: 0.1rem 0.4rem;
		border-radius: 0.35rem;
		background: color-mix(in srgb, var(--system-blue) 12%, transparent);
		font-size: 0.75rem;
		color: var(--label-2);
	}
	.mono {
		font-family: var(--font-mono);
	}
</style>
