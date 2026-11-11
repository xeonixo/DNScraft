/** Client-side bug-report assembly (SPEC.md / SPEC-web-ui.md). Never posts to GitHub. */

export const FEEDBACK_SCHEMA_VERSION = 1;

/** Public GitHub issues endpoint for pre-filled new-issue links. */
export const FEEDBACK_GITHUB_NEW_ISSUE = 'https://github.com/xeonixo/dnscraft/issues/new';

export interface FeedbackDiagnostics {
	schema_version: number;
	dnscraft_version: string | null;
	os: string | null;
	arch: string | null;
	node_role: string | null;
	locale: string;
	route: string;
	error_codes: string[];
	/** Omitted in v1 — needs a diagnostics endpoint (SPEC open question). */
	recent_log_lines: [];
}

export interface FeedbackDraft {
	summary: string;
	expected: string;
	actual: string;
	diagnostics: FeedbackDiagnostics;
}

export function buildDiagnostics(input: {
	locale: string;
	route: string;
	dnscraftVersion?: string | null;
	nodeRole?: string | null;
	errorCodes?: string[];
}): FeedbackDiagnostics {
	return {
		schema_version: FEEDBACK_SCHEMA_VERSION,
		dnscraft_version: input.dnscraftVersion ?? null,
		os: null,
		arch: null,
		node_role: input.nodeRole ?? null,
		locale: input.locale,
		route: input.route,
		error_codes: [...(input.errorCodes ?? [])],
		recent_log_lines: [],
	};
}

export function buildMarkdown(draft: FeedbackDraft): string {
	const diagnostics = JSON.stringify(draft.diagnostics, null, 2);
	return [
		'## Summary',
		'',
		draft.summary.trim() || '(none)',
		'',
		'## Expected',
		'',
		draft.expected.trim() || '(none)',
		'',
		'## Actual',
		'',
		draft.actual.trim() || '(none)',
		'',
		'## Diagnostics',
		'',
		'```json',
		diagnostics,
		'```',
		'',
	].join('\n');
}

/** Opens a pre-filled GitHub issue (`from-product` label). Returns false when popup blocked. */
export function openGitHubIssue(draft: FeedbackDraft): boolean {
	const params = new URLSearchParams({
		title: draft.summary.trim() || 'Feedback from DNScraft UI',
		labels: 'from-product',
		body: buildMarkdown(draft),
	});
	const url = `${FEEDBACK_GITHUB_NEW_ISSUE}?${params.toString()}`;
	const win = window.open(url, '_blank', 'noopener,noreferrer');
	return win !== null;
}

export async function copyMarkdown(draft: FeedbackDraft): Promise<boolean> {
	const text = buildMarkdown(draft);
	try {
		await navigator.clipboard.writeText(text);
		return true;
	} catch {
		return false;
	}
}
