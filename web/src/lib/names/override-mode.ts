import {
	isAddressesOverride,
	rdataTexts,
	rdataWire,
	type AddressesOverride,
	type OverrideValue,
	type RdataValue,
} from '$lib/api/policy';

/** Explicit UI mode for one Netzbereich override. */
export type OverrideMode = 'inherit' | 'public' | 'custom' | 'addresses' | 'no_answer';

export type OverrideRowState = {
	view: string;
	mode: OverrideMode;
	/** Custom CNAME/A/… targets when mode is `custom`. */
	values: string[];
	/** A addresses when mode is `addresses`. */
	a: string[];
	/** AAAA addresses when mode is `addresses`. */
	aaaa: string[];
};

export const PUBLIC_OVERRIDE = '@public';

/** Decode a stored override into an editable row (view already known). */
export function rowFromOverride(view: string, value: OverrideValue): OverrideRowState {
	if (isAddressesOverride(value)) {
		return {
			view,
			mode: 'addresses',
			values: [''],
			a: value.a?.length ? [...value.a] : [''],
			aaaa: value.aaaa?.length ? [...value.aaaa] : [''],
		};
	}
	if (value === '') {
		return { view, mode: 'no_answer', values: [''], a: [''], aaaa: [''] };
	}
	if (value === PUBLIC_OVERRIDE) {
		return { view, mode: 'public', values: [''], a: [''], aaaa: [''] };
	}
	if (typeof value === 'object' && value !== null && 'mode' in value) {
		const structured = value as { mode: string; rdata?: RdataValue };
		if (structured.mode === 'public') {
			return { view, mode: 'public', values: [''], a: [''], aaaa: [''] };
		}
		if (structured.mode === 'no_answer') {
			return { view, mode: 'no_answer', values: [''], a: [''], aaaa: [''] };
		}
		if (structured.mode === 'data') {
			const texts = rdataTexts(structured.rdata);
			return {
				view,
				mode: 'custom',
				values: texts.length > 0 ? texts : [''],
				a: [''],
				aaaa: [''],
			};
		}
	}
	const texts = rdataTexts(value as RdataValue);
	return {
		view,
		mode: 'custom',
		values: texts.length > 0 ? texts : [''],
		a: [''],
		aaaa: [''],
	};
}

/** Build editable rows for every view (missing → inherit). */
export function rowsForViews(
	views: string[],
	overrides: Record<string, OverrideValue>,
): OverrideRowState[] {
	return views.map((view) => {
		const stored = overrides[view];
		if (stored === undefined) {
			return { view, mode: 'inherit', values: [''], a: [''], aaaa: [''] };
		}
		return rowFromOverride(view, stored);
	});
}

/** Encode sparse overrides (skip inherit). */
export function overridesFromRows(rows: OverrideRowState[]): Record<string, OverrideValue> {
	const map: Record<string, OverrideValue> = {};
	for (const row of rows) {
		const view = row.view.trim();
		if (view === '' || row.mode === 'inherit') continue;
		if (row.mode === 'no_answer') {
			map[view] = '';
			continue;
		}
		if (row.mode === 'public') {
			map[view] = PUBLIC_OVERRIDE;
			continue;
		}
		if (row.mode === 'addresses') {
			const a = row.a.map((v) => v.trim()).filter((v) => v !== '');
			const aaaa = row.aaaa.map((v) => v.trim()).filter((v) => v !== '');
			if (a.length === 0 && aaaa.length === 0) continue;
			const wire: AddressesOverride = { mode: 'addresses' };
			if (a.length > 0) wire.a = a;
			if (aaaa.length > 0) wire.aaaa = aaaa;
			map[view] = wire;
			continue;
		}
		const texts = row.values.map((v) => v.trim()).filter((v) => v !== '');
		if (texts.length === 0) continue;
		map[view] = rdataWire(texts);
	}
	return map;
}

/** Short label for list chips / preview. */
export function overridePreview(
	value: OverrideValue | undefined,
	defaultRdata: RdataValue,
): string {
	if (value === undefined) {
		const texts = rdataTexts(defaultRdata);
		return texts.length > 0 ? texts.join(' | ') : '—';
	}
	if (isAddressesOverride(value)) {
		const parts = [...(value.a ?? []), ...(value.aaaa ?? [])];
		return parts.length > 0 ? parts.join(', ') : '—';
	}
	if (value === '') return '∅';
	if (value === PUBLIC_OVERRIDE) return '@public';
	if (typeof value === 'object' && value !== null && 'mode' in value) {
		const structured = value as { mode: string; rdata?: RdataValue };
		if (structured.mode === 'public') return '@public';
		if (structured.mode === 'no_answer') return '∅';
		if (structured.mode === 'data') return rdataTexts(structured.rdata).join(' | ') || '—';
	}
	return rdataTexts(value as RdataValue).join(' | ') || '—';
}
