import { describe, expect, it } from 'vitest';
import { overridesFromRows, rowFromOverride, rowsForViews, overridePreview } from './override-mode';

describe('override-mode', () => {
	it('maps legacy wires to modes', () => {
		expect(rowFromOverride('lan', '@public').mode).toBe('public');
		expect(rowFromOverride('lan', '').mode).toBe('no_answer');
		expect(rowFromOverride('lan', '10.0.0.1').mode).toBe('custom');
		expect(rowFromOverride('lan', { mode: 'addresses', a: ['10.0.0.5'] }).mode).toBe('addresses');
	});

	it('omits inherit rows when encoding', () => {
		const map = overridesFromRows([
			{ view: 'lan', mode: 'inherit', values: [''], a: [''], aaaa: [''] },
			{ view: 'guests', mode: 'public', values: [''], a: [''], aaaa: [''] },
			{
				view: 'home',
				mode: 'addresses',
				values: [''],
				a: ['10.0.0.5'],
				aaaa: ['fd00::5'],
			},
		]);
		expect(map).toEqual({
			guests: '@public',
			home: { mode: 'addresses', a: ['10.0.0.5'], aaaa: ['fd00::5'] },
		});
	});

	it('builds a full matrix with inherit defaults', () => {
		const rows = rowsForViews(['lan', 'guests'], { guests: '' });
		expect(rows).toHaveLength(2);
		expect(rows[0].mode).toBe('inherit');
		expect(rows[1].mode).toBe('no_answer');
	});

	it('previews defaults and addresses', () => {
		expect(overridePreview(undefined, 'cdn.example.net.')).toBe('cdn.example.net.');
		expect(overridePreview({ mode: 'addresses', a: ['10.0.0.5'] }, 'x')).toBe('10.0.0.5');
		expect(overridePreview('@public', 'x')).toBe('@public');
	});
});
