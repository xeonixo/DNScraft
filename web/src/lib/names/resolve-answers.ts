import {
	isAddressesOverride,
	rdataTexts,
	type OverrideValue,
	type PolicyRecord,
	type RdataValue,
} from '$lib/api/policy';
import { overridePreview, PUBLIC_OVERRIDE } from './override-mode';

export type ResolvedAnswer = {
	view: string;
	/** Short human label for chips. */
	label: string;
	/** Whether this view differs from the record default. */
	deviant: boolean;
	mode: 'inherit' | 'public' | 'custom' | 'addresses' | 'no_answer';
};

/** Effective answer summary per view for list chips / sheet preview. */
export function resolveAnswersForRecord(record: PolicyRecord, viewIds: string[]): ResolvedAnswer[] {
	return viewIds.map((view) => {
		const value = record.overrides[view];
		if (value === undefined) {
			return {
				view,
				label: overridePreview(undefined, record.rdata),
				deviant: false,
				mode: 'inherit',
			};
		}
		if (isAddressesOverride(value)) {
			return {
				view,
				label: overridePreview(value, record.rdata),
				deviant: true,
				mode: 'addresses',
			};
		}
		if (
			value === '' ||
			(typeof value === 'object' &&
				value !== null &&
				(value as { mode?: string }).mode === 'no_answer')
		) {
			return { view, label: '∅', deviant: true, mode: 'no_answer' };
		}
		if (
			value === PUBLIC_OVERRIDE ||
			(typeof value === 'object' &&
				value !== null &&
				(value as { mode?: string }).mode === 'public')
		) {
			return { view, label: '@public', deviant: true, mode: 'public' };
		}
		return {
			view,
			label: overridePreview(value, record.rdata),
			deviant: true,
			mode: 'custom',
		};
	});
}

/**
 * Flat CNAME chain preview from the loaded record set (no live DNS).
 * Stops at external targets, addresses overrides, loops, or max hops.
 */
export function cnameChainPreview(
	owner: string,
	view: string,
	records: PolicyRecord[],
	maxHops = 8,
): string[] {
	const byName = new Map<string, PolicyRecord[]>();
	for (const record of records) {
		const key = record.name.replace(/\.$/, '').toLowerCase();
		const list = byName.get(key) ?? [];
		list.push(record);
		byName.set(key, list);
	}

	const chain: string[] = [];
	const seen = new Set<string>();
	let current = owner.replace(/\.$/, '').toLowerCase();

	for (let hop = 0; hop < maxHops; hop++) {
		if (seen.has(current)) {
			chain.push('…');
			break;
		}
		seen.add(current);
		const atOwner = byName.get(current) ?? [];
		const cname = atOwner.find((r) => r.type.toUpperCase() === 'CNAME');
		if (!cname) {
			const a = atOwner.find((r) => r.type.toUpperCase() === 'A');
			const aaaa = atOwner.find((r) => r.type.toUpperCase() === 'AAAA');
			const parts = [
				...(a ? rdataTexts(effectiveRdata(a, view)) : []),
				...(aaaa ? rdataTexts(effectiveRdata(aaaa, view)) : []),
			];
			if (parts.length > 0) chain.push(parts.join(', '));
			break;
		}
		const ov = cname.overrides[view];
		if (isAddressesOverride(ov)) {
			const parts = [...(ov.a ?? []), ...(ov.aaaa ?? [])];
			chain.push(parts.join(', ') || '—');
			break;
		}
		if (ov === PUBLIC_OVERRIDE) {
			chain.push('@public');
			break;
		}
		if (ov === '') {
			chain.push('∅');
			break;
		}
		const targets = rdataTexts(effectiveRdata(cname, view));
		if (targets.length === 0) break;
		const next = targets[0].replace(/\.$/, '').toLowerCase();
		chain.push(targets.length > 1 ? `${targets.join(' | ')} (rotiert)` : targets[0]);
		if (!byName.has(next)) {
			chain.push('(extern)');
			break;
		}
		current = next;
	}
	return chain;
}

function effectiveRdata(record: PolicyRecord, view: string): RdataValue {
	const ov = record.overrides[view];
	if (ov === undefined) return record.rdata;
	if (isAddressesOverride(ov) || ov === '' || ov === PUBLIC_OVERRIDE) return '';
	if (typeof ov === 'object' && ov !== null && 'mode' in ov) {
		const structured = ov as { mode: string; rdata?: RdataValue };
		if (structured.mode === 'data') return structured.rdata ?? '';
		return '';
	}
	return ov as OverrideValue as RdataValue;
}
