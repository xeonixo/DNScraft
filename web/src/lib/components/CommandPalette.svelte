<script lang="ts">
	import { tick } from 'svelte';
	import { goto } from '$app/navigation';
	import { m } from '$lib/paraglide/messages';
	import type { Role } from '$lib/nav';
	import {
		paletteEntries,
		type PaletteEntry,
		type PaletteSection,
		type PaletteSource,
	} from '$lib/palette/entries';

	interface Props {
		role?: Role;
		/** Nav catalog. Tests pass a fixture; the shell uses the real sidebar. */
		source?: PaletteSource;
	}

	let { role = 'viewer', source }: Props = $props();

	const uid = $props.id();
	const titleId = `${uid}-title`;
	const listId = `${uid}-list`;
	const hintId = `${uid}-hint`;

	const NON_TEXT_INPUT = new Set([
		'button',
		'checkbox',
		'color',
		'file',
		'hidden',
		'image',
		'radio',
		'range',
		'reset',
		'submit',
	]);

	const FOCUSABLE =
		'a[href]:not([tabindex="-1"]), button:not([disabled]):not([tabindex="-1"]), input:not([disabled]):not([tabindex="-1"]), select:not([disabled]), textarea:not([disabled])';

	let open = $state(false);
	let query = $state('');
	let active = $state(0);
	let inputEl = $state<HTMLInputElement | undefined>();
	let dialog = $state<HTMLDivElement | undefined>();

	const entries = $derived(paletteEntries(role, query, source));
	const selected = $derived(entries.length === 0 ? -1 : Math.min(active, entries.length - 1));
	const groups = $derived(groupEntries(entries));

	function optionId(index: number): string {
		return `${uid}-opt-${index}`;
	}

	function groupEntries(
		items: PaletteEntry[],
	): { id: PaletteSection; label: string; items: (PaletteEntry & { index: number })[] }[] {
		const sections: {
			id: PaletteSection;
			label: string;
			items: (PaletteEntry & { index: number })[];
		}[] = [
			{ id: 'domains', label: m.palette_section_domains(), items: [] },
			{ id: 'navigation', label: m.palette_section_navigation(), items: [] },
		];
		items.forEach((entry, index) => {
			sections.find((section) => section.id === entry.section)?.items.push({ ...entry, index });
		});
		return sections.filter((section) => section.items.length > 0);
	}

	/** Text fields keep their own shortcuts; Cmd/Ctrl+K does not open over them. */
	function isTypingTarget(target: EventTarget | null): boolean {
		if (!(target instanceof HTMLElement)) return false;
		if (target.isContentEditable) return true;
		if (target.tagName === 'TEXTAREA' || target.tagName === 'SELECT') return true;
		if (target.tagName !== 'INPUT') return false;
		return !NON_TEXT_INPUT.has((target as HTMLInputElement).type);
	}

	function isPaletteChord(event: KeyboardEvent): boolean {
		if (event.repeat || event.altKey || event.shiftKey) return false;
		if (!event.metaKey && !event.ctrlKey) return false;
		return event.key.toLowerCase() === 'k';
	}

	function onWindowKeydown(event: KeyboardEvent): void {
		if (open && event.key === 'Escape') {
			event.preventDefault();
			event.stopPropagation();
			open = false;
			return;
		}
		if (!isPaletteChord(event)) return;
		// Closed, and the user is typing, or another dialog is up: leave the shortcut alone.
		if (!open && (isTypingTarget(event.target) || document.querySelector('[role="dialog"]')))
			return;
		event.preventDefault();
		event.stopPropagation();
		if (open) {
			open = false;
			return;
		}
		query = '';
		active = 0;
		open = true;
	}

	function moveBy(delta: number): void {
		if (entries.length === 0) return;
		active = (active + delta + entries.length) % entries.length;
	}

	function activate(index: number): void {
		const entry = entries[index];
		if (!entry) return;
		open = false;
		// entry.href is already resolve()'d (nav paths) or listHref()'d (query-log filter).
		// eslint-disable-next-line svelte/no-navigation-without-resolve
		void goto(entry.href);
	}

	function trapTab(event: KeyboardEvent): void {
		if (!dialog) return;
		const items = [...dialog.querySelectorAll<HTMLElement>(FOCUSABLE)];
		const first = items[0];
		const last = items[items.length - 1];
		const current = document.activeElement;
		const inside = current instanceof Node && dialog.contains(current);
		if (!first || !last) {
			event.preventDefault();
			return;
		}
		if (event.shiftKey && (!inside || current === first)) {
			event.preventDefault();
			last.focus();
		} else if (!event.shiftKey && (!inside || current === last)) {
			event.preventDefault();
			first.focus();
		}
	}

	function onDialogKey(event: KeyboardEvent): void {
		switch (event.key) {
			case 'Escape':
				event.preventDefault();
				event.stopPropagation();
				open = false;
				return;
			case 'ArrowDown':
				event.preventDefault();
				moveBy(1);
				return;
			case 'ArrowUp':
				event.preventDefault();
				moveBy(-1);
				return;
			case 'Home':
				event.preventDefault();
				active = 0;
				return;
			case 'End':
				event.preventDefault();
				active = Math.max(0, entries.length - 1);
				return;
			case 'Enter':
				event.preventDefault();
				if (selected >= 0) activate(selected);
				return;
			case 'Tab':
				trapTab(event);
				return;
		}
	}

	// Opening moves focus to the combobox; closing returns it to whatever opened the palette.
	$effect(() => {
		if (!open) return;
		const trigger = document.activeElement;
		let alive = true;
		void tick().then(() => {
			if (alive) inputEl?.focus();
		});
		return () => {
			alive = false;
			if (trigger instanceof HTMLElement && trigger.isConnected) trigger.focus();
		};
	});

	$effect(() => {
		if (!open || selected < 0) return;
		const option = document.getElementById(optionId(selected));
		if (typeof option?.scrollIntoView === 'function') option.scrollIntoView({ block: 'nearest' });
	});
</script>

<svelte:window onkeydowncapture={onWindowKeydown} />

{#if open}
	<button
		type="button"
		class="scrim"
		tabindex="-1"
		aria-label={m.palette_close()}
		onclick={() => (open = false)}
	></button>
	<div class="layer">
		<div
			class="dialog"
			role="dialog"
			aria-modal="true"
			aria-labelledby={titleId}
			tabindex="-1"
			bind:this={dialog}
			onkeydown={onDialogKey}
		>
			<h2 id={titleId} class="sr-only">{m.palette_title()}</h2>
			<input
				bind:this={inputEl}
				class="field"
				type="text"
				role="combobox"
				aria-label={m.palette_input_label()}
				aria-autocomplete="list"
				aria-expanded={entries.length > 0}
				aria-controls={listId}
				aria-activedescendant={selected >= 0 ? optionId(selected) : undefined}
				aria-describedby={hintId}
				placeholder={m.palette_placeholder()}
				autocomplete="off"
				autocapitalize="none"
				spellcheck="false"
				value={query}
				oninput={(event) => {
					query = event.currentTarget.value;
					active = 0;
				}}
			/>
			<div
				id={listId}
				class="list"
				role="listbox"
				aria-label={m.palette_results_label()}
				hidden={entries.length === 0}
			>
				{#each groups as group (group.id)}
					<div role="group" aria-label={group.label}>
						<div class="group-label" aria-hidden="true">{group.label}</div>
						{#each group.items as entry (entry.id)}
							<button
								type="button"
								class="option"
								class:domain={entry.section === 'domains'}
								role="option"
								id={optionId(entry.index)}
								tabindex="-1"
								aria-selected={entry.index === selected}
								onmousedown={(event) => event.preventDefault()}
								onmouseenter={() => (active = entry.index)}
								onclick={() => activate(entry.index)}
							>
								{entry.label}
							</button>
						{/each}
					</div>
				{/each}
			</div>
			{#if entries.length === 0}
				<p class="empty">{m.palette_empty()}</p>
			{/if}
			<p id={hintId} class="hint">{m.palette_hint()}</p>
			<div class="sr-only" aria-live="polite" aria-atomic="true">
				{m.palette_result_count({ count: entries.length })}
			</div>
		</div>
	</div>
{/if}

<style>
	.scrim {
		position: fixed;
		inset: 0;
		z-index: 80;
		padding: 0;
		border: 0;
		background: var(--scrim);
		cursor: default;
	}

	.layer {
		position: fixed;
		inset: 0;
		z-index: 81;
		display: grid;
		place-items: start center;
		padding: max(10vh, calc(env(safe-area-inset-top) + 1rem)) 1rem 1rem;
		pointer-events: none;
	}

	.dialog {
		display: flex;
		flex-direction: column;
		width: min(32rem, 100%);
		max-height: min(36rem, calc(100dvh - 8rem));
		padding: 0.875rem;
		overflow: hidden;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow-sheet);
		pointer-events: auto;
	}

	.dialog:focus {
		outline: none;
	}

	.field {
		box-sizing: border-box;
		width: 100%;
		min-height: var(--control-h);
		padding: 0.5rem 0.75rem;
		background: var(--surface-2);
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		color: var(--label);
		font: inherit;
		font-size: 0.9375rem;
	}

	.list {
		margin-top: 0.625rem;
		overflow-y: auto;
		overscroll-behavior: contain;
	}

	.group-label {
		padding: 0.5rem 0.75rem 0.25rem;
		color: var(--label-2);
		font-size: 0.75rem;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
	}

	.option {
		display: flex;
		align-items: center;
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 0;
		border-radius: var(--r-ctl);
		background: transparent;
		color: var(--label);
		font: inherit;
		text-align: start;
		overflow-wrap: anywhere;
		cursor: pointer;
	}

	.option.domain {
		font-family: var(--font-mono);
		font-size: 0.875rem;
	}

	.option[aria-selected='true'] {
		background: var(--accent-fill);
		color: var(--accent);
	}

	.empty,
	.hint {
		margin: 0.625rem 0.25rem 0;
		color: var(--label-2);
		font-size: 0.8125rem;
	}
</style>
