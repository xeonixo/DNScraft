<script lang="ts">
	import { m } from '$lib/paraglide/messages';

	interface Props {
		types: string[];
		tags: string[];
		typeFilter: string;
		tagFilter: string;
		deviationsOnly: boolean;
		publicOnly: boolean;
	}

	let {
		types,
		tags,
		typeFilter = $bindable(''),
		tagFilter = $bindable(''),
		deviationsOnly = $bindable(false),
		publicOnly = $bindable(false),
	}: Props = $props();
</script>

<div class="filters" role="group" aria-label={m.names_filter_type()}>
	<button
		type="button"
		class="chip"
		aria-pressed={typeFilter === ''}
		onclick={() => (typeFilter = '')}>{m.names_filter_type_all()}</button
	>
	{#each types as type (type)}
		<button
			type="button"
			class="chip"
			aria-pressed={typeFilter === type}
			onclick={() => (typeFilter = typeFilter === type ? '' : type)}>{type}</button
		>
	{/each}
</div>

{#if tags.length > 0}
	<div class="filters" role="group" aria-label={m.names_filter_tags()}>
		{#each tags as tag (tag)}
			<button
				type="button"
				class="chip"
				aria-pressed={tagFilter === tag}
				onclick={() => (tagFilter = tagFilter === tag ? '' : tag)}>{tag}</button
			>
		{/each}
	</div>
{/if}

<div class="toggles">
	<label class="toggle">
		<input type="checkbox" bind:checked={deviationsOnly} />
		{m.names_filter_deviations()}
	</label>
	<label class="toggle">
		<input type="checkbox" bind:checked={publicOnly} />
		{m.names_filter_public()}
	</label>
</div>

<style>
	.filters {
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem;
		margin: 0.75rem 0 0.35rem;
	}
	.chip {
		border: 1px solid color-mix(in srgb, var(--label) 18%, transparent);
		background: transparent;
		border-radius: 999px;
		padding: 0.25rem 0.7rem;
		font: inherit;
		cursor: pointer;
		color: inherit;
	}
	.chip[aria-pressed='true'] {
		background: color-mix(in srgb, var(--system-blue) 18%, transparent);
		border-color: var(--system-blue);
	}
	.toggles {
		display: flex;
		flex-wrap: wrap;
		gap: 0.75rem 1.25rem;
		margin: 0.35rem 0 0.75rem;
		font-size: 0.9rem;
	}
	.toggle {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
		cursor: pointer;
	}
</style>
