<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { ApiError } from '$lib/api/client';
	import { authBootstrapStatus } from '$lib/api/auth';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import { auth } from '$lib/auth/state.svelte';
	import { bootstrapLocal, loadMe } from '$lib/auth/store.svelte';
	import LocaleSwitcher from '$lib/i18n/LocaleSwitcher.svelte';
	import { CLIENT_NETWORK } from '$lib/api/error-codes';
	import { m } from '$lib/paraglide/messages';

	interface Failure {
		code: string;
		params: Record<string, unknown>;
	}

	let username = $state('');
	let password = $state('');
	let confirm = $state('');
	let submitting = $state(false);
	let failure = $state<Failure | null>(null);
	let localFailure = $state<string | null>(null);
	let phase = $state<'loading' | 'form' | 'done' | 'unavailable'>('loading');

	function failureOf(error: unknown): Failure {
		if (error instanceof ApiError) return { code: error.code, params: error.params };
		return { code: CLIENT_NETWORK, params: {} };
	}

	onMount(() => {
		if (auth.status === 'authenticated') {
			phase = 'done';
			return;
		}
		void authBootstrapStatus()
			.then((status) => {
				if (status.needs_setup && status.local_login) {
					phase = 'form';
					return;
				}
				if (!status.needs_setup) {
					void goto(resolve('/login'), { replaceState: true });
					return;
				}
				phase = 'unavailable';
			})
			.catch((error) => {
				failure = failureOf(error);
				phase = 'unavailable';
			});
	});

	async function createAdmin(event: SubmitEvent): Promise<void> {
		event.preventDefault();
		if (submitting) return;
		localFailure = null;
		failure = null;
		if (password.length < 8) {
			localFailure = 'short';
			return;
		}
		if (password !== confirm) {
			localFailure = 'mismatch';
			return;
		}
		submitting = true;
		try {
			await bootstrapLocal(username, password);
			await loadMe();
			phase = 'done';
		} catch (error) {
			failure = failureOf(error);
			if (error instanceof ApiError && error.code === 'control_api.auth.bootstrap_taken') {
				void goto(resolve('/login'), { replaceState: true });
			}
		} finally {
			password = '';
			confirm = '';
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>{m.document_title({ page: m.setup_title(), app: m.app_name() })}</title>
</svelte:head>

<main class="setup">
	<header class="intro">
		<img class="logo" src="/favicon.svg" alt="" width="72" height="72" />
		<h1>{m.setup_title()}</h1>
		{#if phase === 'form'}
			<p class="lead">{m.setup_lead()}</p>
		{/if}
	</header>

	{#if phase === 'loading'}
		<p class="pending">{m.state_loading()}</p>
	{:else if phase === 'unavailable'}
		<GroupedList>
			<div class="row">
				{#if failure}
					<ErrorNotice code={failure.code} params={failure.params} />
				{:else}
					<p>{m.setup_unavailable()}</p>
				{/if}
				<a class="link" href={resolve('/login')}>{m.setup_to_login()}</a>
			</div>
		</GroupedList>
	{:else if phase === 'form'}
		<GroupedList>
			<form class="row form" onsubmit={createAdmin}>
				{#if failure}
					<ErrorNotice code={failure.code} params={failure.params} />
				{/if}
				{#if localFailure === 'mismatch'}
					<p class="local-error" role="alert">{m.setup_password_mismatch()}</p>
				{:else if localFailure === 'short'}
					<p class="local-error" role="alert">{m.setup_password_too_short()}</p>
				{/if}

				<label class="field">
					<span>{m.login_username_label()}</span>
					<input
						name="username"
						autocomplete="username"
						autocapitalize="none"
						spellcheck="false"
						required
						bind:value={username}
						disabled={submitting}
					/>
				</label>

				<label class="field">
					<span>{m.login_password_label()}</span>
					<input
						type="password"
						name="password"
						autocomplete="new-password"
						required
						minlength="8"
						bind:value={password}
						disabled={submitting}
					/>
				</label>

				<label class="field">
					<span>{m.setup_password_confirm_label()}</span>
					<input
						type="password"
						name="confirm"
						autocomplete="new-password"
						required
						minlength="8"
						bind:value={confirm}
						disabled={submitting}
					/>
				</label>

				<Button type="submit" variant="primary" disabled={submitting}>
					{submitting ? m.setup_submitting() : m.setup_submit()}
				</Button>
			</form>
		</GroupedList>
	{:else}
		<GroupedList>
			<div class="row">
				<h2 class="next-title">{m.setup_next_title()}</h2>
				<p>{m.setup_next_lead()}</p>
				<a class="link" href={resolve('/profiles')}>{m.setup_next_profiles()}</a>
				<a class="link" href={resolve('/rules')}>{m.setup_next_rules()}</a>
				<a class="link primary" href={resolve('/dashboard')}>{m.setup_next_dashboard()}</a>
			</div>
		</GroupedList>
	{/if}

	<div class="prefs">
		<LocaleSwitcher />
	</div>
</main>

<style>
	.setup {
		display: flex;
		flex-direction: column;
		gap: var(--space-5);
		box-sizing: border-box;
		width: 100%;
		max-width: 27.5rem;
		min-height: 100dvh;
		margin: 0 auto;
		padding: var(--space-6) var(--space-4);
		justify-content: center;
	}

	.intro {
		text-align: center;
	}

	.logo {
		display: block;
		margin: 0 auto;
		filter: drop-shadow(0 4px 12px var(--shadow-color, transparent));
	}

	.intro h1 {
		margin: var(--space-3) 0 0;
		font-size: 1.5rem;
		font-weight: 700;
		letter-spacing: -0.02em;
		color: var(--label);
	}

	.lead,
	.pending,
	.row p {
		margin: var(--space-2) 0 0;
		color: var(--label-2);
	}

	.prefs {
		position: absolute;
		top: var(--space-4);
		right: var(--space-4);
	}

	.row {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-4);
	}

	.form :global(.btn) {
		width: 100%;
	}

	.form {
		align-items: stretch;
	}

	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		font-size: 0.875rem;
		color: var(--label-2);
	}

	input {
		box-sizing: border-box;
		width: 100%;
		min-height: 2.75rem;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface-2);
		color: var(--label);
		font: inherit;
		font-size: 1rem;
	}

	input:disabled {
		opacity: 0.6;
	}

	.local-error {
		margin: 0;
		color: var(--danger);
	}

	.next-title {
		margin: 0;
		font-size: 1.125rem;
		color: var(--label);
	}

	.link {
		color: var(--accent);
		text-decoration: none;
		min-height: 2.75rem;
		display: inline-flex;
		align-items: center;
	}

	.link.primary {
		font-weight: 600;
	}
</style>
