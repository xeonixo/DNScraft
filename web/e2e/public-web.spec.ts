import { test, expect } from './fixtures';

async function signInAsAdmin(page: import('@playwright/test').Page): Promise<void> {
	await page.goto('/login');
	await page.getByLabel(/username|benutzername/i).fill('admin');
	await page.getByLabel(/password|passwort/i).fill('any');
	await page
		.locator('form')
		.getByRole('button', { name: /sign in|anmelden/i })
		.click();
	await expect(page).toHaveURL(/\/dashboard/);
}

test.describe('public web access', () => {
	test('toggles public access, saves CIDRs, and lifts a ban', async ({ page }) => {
		await signInAsAdmin(page);
		await page.goto('/settings');

		const accessSwitch = page.getByRole('switch', {
			name: /web ui reachable|web-ui .*erreichbar/i,
		});
		await expect(accessSwitch).toBeVisible();
		await accessSwitch.scrollIntoViewIfNeeded();
		// Custom track/thumb overlays the native control; drive the checkbox directly.
		await accessSwitch.evaluate((el) => {
			const input = el as HTMLInputElement;
			input.checked = !input.checked;
			input.dispatchEvent(new Event('change', { bubbles: true }));
		});
		await expect(accessSwitch).toBeChecked();
		await expect(
			page.locator('.detail', { hasText: /publicly reachable|öffentlich/i }),
		).toBeVisible();

		const cidrs = page.locator('textarea.cidrs-input');
		await expect(cidrs).toBeVisible();
		await cidrs.fill('203.0.113.0/24\n198.51.100.0/24');
		await cidrs.blur();
		await expect(cidrs).toHaveValue(/203\.0\.113\.0\/24/);

		const banLabel = page.getByText('198.51.100.7', { exact: true });
		await expect(banLabel).toBeVisible();
		await page
			.getByRole('button', { name: /unban|entsperren/i })
			.first()
			.click();
		await expect(banLabel).toHaveCount(0);

		await expect(page.getByRole('link', { name: /listener ban|listener-ban/i })).toHaveAttribute(
			'href',
			/\/listeners/,
		);
	});
});
