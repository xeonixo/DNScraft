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

<div class="bar">
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
</div>

<style>
	.bar {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.5rem 1.25rem;
	}
	.filters {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
	}
	.chip {
		border: 1px solid color-mix(in srgb, var(--label) 18%, transparent);
		background: transparent;
		border-radius: 999px;
		padding: 0.2rem 0.65rem;
		font: inherit;
		font-size: 0.8125rem;
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
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.toggle {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
		cursor: pointer;
	}
</style>
