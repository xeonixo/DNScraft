<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import Button from '$lib/components/Button.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import { getStatus } from '$lib/api/stats';
	import {
		buildDiagnostics,
		buildMarkdown,
		copyMarkdown,
		openGitHubIssue,
		type FeedbackDiagnostics,
	} from '$lib/feedback';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';

	let summary = $state('');
	let expected = $state('');
	let actual = $state('');
	let version = $state<string | null>(null);
	let nodeRole = $state<string | null>(null);
	let status = $state<'idle' | 'copied' | 'copy_failed' | 'popup_blocked'>('idle');

	const diagnostics = $derived<FeedbackDiagnostics>(
		buildDiagnostics({
			locale: getLocale(),
			route: page.url.pathname,
			dnscraftVersion: version,
			nodeRole,
		}),
	);

	const draft = $derived({
		summary,
		expected,
		actual,
		diagnostics,
	});

	const preview = $derived(buildMarkdown(draft));
	const canSubmit = $derived(summary.trim().length > 0);

	onMount(() => {
		void getStatus()
			.then((data) => {
				version = data.version || null;
				nodeRole = data.cluster?.role ?? 'standalone';
			})
			.catch(() => {
				version = null;
				nodeRole = null;
			});
	});

	function openIssue(): void {
		status = 'idle';
		if (!openGitHubIssue(draft)) {
			status = 'popup_blocked';
		}
	}

	async function copy(): Promise<void> {
		status = 'idle';
		status = (await copyMarkdown(draft)) ? 'copied' : 'copy_failed';
	}
</script>

<p class="lead">{m.feedback_lead()}</p>

<form
	class="form"
	onsubmit={(event) => {
		event.preventDefault();
		openIssue();
	}}
>
	<label class="field">
		<span>{m.feedback_summary_label()}</span>
		<textarea bind:value={summary} rows="3" required maxlength="500"></textarea>
	</label>
	<label class="field">
		<span>{m.feedback_expected_label()}</span>
		<textarea bind:value={expected} rows="3" maxlength="2000"></textarea>
	</label>
	<label class="field">
		<span>{m.feedback_actual_label()}</span>
		<textarea bind:value={actual} rows="3" maxlength="2000"></textarea>
	</label>

	<GroupedList header={m.feedback_diagnostics_heading()}>
		<GroupedRow
			label={m.feedback_diagnostics_version()}
			detail={version ? `v${version}` : m.feedback_diagnostics_unknown()}
		/>
		<GroupedRow
			label={m.feedback_diagnostics_locale()}
			detail={getLocale()}
		/>
		<GroupedRow
			label={m.feedback_diagnostics_role()}
			detail={nodeRole ?? m.feedback_diagnostics_unknown()}
		/>
		<GroupedRow label={m.feedback_diagnostics_logs()} detail={m.feedback_diagnostics_logs_omitted()} />
	</GroupedList>

	<p class="hint">{m.feedback_privacy_note()}</p>

	<div class="actions">
		<Button type="submit" variant="primary" disabled={!canSubmit}>
			{m.feedback_open_github()}
		</Button>
		<Button type="button" variant="secondary" onclick={() => void copy()}>
			{m.feedback_copy_markdown()}
		</Button>
	</div>

	{#if status === 'copied'}
		<p class="status ok" role="status">{m.feedback_copied()}</p>
	{:else if status === 'copy_failed'}
		<p class="status err" role="status">{m.feedback_copy_failed()}</p>
	{:else if status === 'popup_blocked'}
		<p class="status err" role="status">{m.feedback_popup_blocked()}</p>
	{/if}
</form>

<details class="preview">
	<summary>{m.feedback_preview_heading()}</summary>
	<pre>{preview}</pre>
</details>

<style>
	.lead {
		margin: 0 0 1.25rem;
		color: var(--label-2);
		max-width: 40rem;
	}

	.form {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		max-width: 40rem;
	}

	.field {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		color: var(--label-1);
		font-size: 0.875rem;
	}

	.field textarea {
		resize: vertical;
		min-height: 4.5rem;
		padding: 0.65rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
		color: var(--label-1);
		font: inherit;
	}

	.hint {
		margin: 0;
		font-size: 0.8125rem;
		color: var(--label-3);
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.75rem;
	}

	.status {
		margin: 0;
		font-size: 0.875rem;
	}

	.status.ok {
		color: var(--label-2);
	}

	.status.err {
		color: var(--danger, #b42318);
	}

	.preview {
		margin-top: 1.5rem;
		max-width: 40rem;
		color: var(--label-2);
	}

	.preview pre {
		margin: 0.75rem 0 0;
		padding: 0.75rem;
		overflow: auto;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		font-size: 0.75rem;
		white-space: pre-wrap;
	}
</style>
