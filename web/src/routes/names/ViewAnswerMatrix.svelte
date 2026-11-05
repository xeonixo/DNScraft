<script lang="ts">
	import Segmented from '$lib/components/Segmented.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import type { OverrideMode, OverrideRowState } from '$lib/names/override-mode';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		rows: OverrideRowState[];
		recordType: string;
		readonly?: boolean;
		chainByView?: Record<string, string>;
		onrowschange?: (rows: OverrideRowState[]) => void;
	}

	let {
		rows = $bindable(),
		recordType,
		readonly = false,
		chainByView = {},
		onrowschange,
	}: Props = $props();

	const isCname = $derived(recordType.trim().toUpperCase() === 'CNAME');

	function modeOptions(): { value: OverrideMode; label: string }[] {
		const base: { value: OverrideMode; label: string }[] = [
			{ value: 'inherit', label: m.names_mode_inherit() },
			{ value: 'public', label: m.names_mode_public() },
			{ value: 'custom', label: m.names_mode_custom() },
		];
		if (isCname) {
			base.push({ value: 'addresses', label: m.names_mode_addresses() });
		}
		base.push({ value: 'no_answer', label: m.names_mode_no_answer() });
		return base;
	}

	function setMode(index: number, mode: OverrideMode): void {
		rows = rows.map((row, i) => (i === index ? { ...row, mode } : row));
		onrowschange?.(rows);
	}

	function setValues(index: number, values: string[]): void {
		rows = rows.map((row, i) => (i === index ? { ...row, values } : row));
		onrowschange?.(rows);
	}

	function setA(index: number, a: string[]): void {
		rows = rows.map((row, i) => (i === index ? { ...row, a } : row));
		onrowschange?.(rows);
	}

	function setAaaa(index: number, aaaa: string[]): void {
		rows = rows.map((row, i) => (i === index ? { ...row, aaaa } : row));
		onrowschange?.(rows);
	}
</script>

{#if rows.length === 0}
	<p class="hint muted">{m.names_overrides_empty_standard()}</p>
{:else}
	<ul class="matrix" aria-label={m.names_section_overrides()}>
		{#each rows as row, i (row.view)}
			<li class="matrix-row">
				<p class="view-id mono">{row.view}</p>
				{#if !readonly}
					<Segmented
						options={modeOptions()}
						value={row.mode}
						label={m.names_mode_label()}
						onchange={(mode) => setMode(i, mode)}
					/>
				{:else}
					<p class="mode-label">{row.mode}</p>
				{/if}
				{#if row.mode === 'custom'}
					<div class="values">
						{#each row.values as text, j (j)}
							<input
								class="field mono"
								type="text"
								value={text}
								disabled={readonly}
								aria-label={j === 0
									? m.names_overrides_value()
									: m.names_value_extra({ n: String(j + 1) })}
								oninput={(event) => {
									const next = [...row.values];
									next[j] = event.currentTarget.value;
									setValues(i, next);
								}}
							/>
						{/each}
						{#if !readonly}
							<button type="button" class="add" onclick={() => setValues(i, [...row.values, ''])}>
								{m.names_value_add()}
							</button>
						{/if}
					</div>
				{:else if row.mode === 'addresses'}
					<div class="values">
						<label class="sr-only" for="a-{row.view}">{m.names_field_a()}</label>
						{#each row.a as text, j (j)}
							<input
								id={j === 0 ? `a-${row.view}` : undefined}
								class="field mono"
								type="text"
								value={text}
								disabled={readonly}
								placeholder={m.names_field_a()}
								oninput={(event) => {
									const next = [...row.a];
									next[j] = event.currentTarget.value;
									setA(i, next);
								}}
							/>
						{/each}
						{#if !readonly}
							<button type="button" class="add" onclick={() => setA(i, [...row.a, ''])}
								>{m.names_value_add()}</button
							>
						{/if}
						{#each row.aaaa as text, j (j)}
							<input
								class="field mono"
								type="text"
								value={text}
								disabled={readonly}
								placeholder={m.names_field_aaaa()}
								oninput={(event) => {
									const next = [...row.aaaa];
									next[j] = event.currentTarget.value;
									setAaaa(i, next);
								}}
							/>
						{/each}
						{#if !readonly}
							<button type="button" class="add" onclick={() => setAaaa(i, [...row.aaaa, ''])}
								>{m.names_value_add()}</button
							>
						{/if}
					</div>
				{:else if row.mode === 'no_answer' && !readonly}
					<div class="no-answer">
						<span>{m.names_overrides_no_answer()}</span>
						<Switch checked={true} disabled aria-label={m.names_overrides_no_answer()} />
					</div>
				{/if}
				{#if chainByView[row.view]}
					<p class="chain hint muted">
						{m.names_chain_preview()}: {chainByView[row.view]}
					</p>
				{/if}
			</li>
		{/each}
	</ul>
{/if}

<style>
	.matrix {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}
	.matrix-row {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		padding-bottom: 0.75rem;
		border-bottom: 1px solid color-mix(in srgb, var(--label) 12%, transparent);
	}
	.view-id {
		font-weight: 600;
		margin: 0;
	}
	.values {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.field {
		width: 100%;
	}
	.add {
		align-self: flex-start;
		background: none;
		border: none;
		color: var(--system-blue);
		cursor: pointer;
		padding: 0;
		font: inherit;
	}
	.chain {
		margin: 0;
		font-size: 0.85rem;
	}
	.no-answer {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	.mode-label {
		margin: 0;
		opacity: 0.8;
	}
	.hint {
		margin: 0;
	}
	.muted {
		opacity: 0.7;
	}
</style>
