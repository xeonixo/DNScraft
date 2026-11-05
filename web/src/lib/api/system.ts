import { del, get, put } from './client';

/** `GET /api/v1/update/check` (system_routes.rs). */
export interface UpdateCheck {
	enabled: boolean;
	current: string;
	latest: string | null;
	update_available: boolean;
	release_url: string | null;
	checked_at: string | null;
	error?: { code: string };
}

/** `GET/PUT /api/v1/web-access` (system_routes.rs): public sources may reach the web UI. */
export interface WebAccess {
	public_enabled: boolean;
	/** Empty means no extra restriction on public sources. */
	allowed_cidrs: string[];
	version?: number;
}

export const getWebAccess = (): Promise<WebAccess> => get('/web-access');
export const putWebAccess = (body: {
	public_enabled: boolean;
	allowed_cidrs: string[];
}): Promise<WebAccess> => put('/web-access', { body });

/** `GET /api/v1/web-bans`: sources currently banned by the shared strike table. */
export interface WebBan {
	ip: string;
	until: string;
}

export const getWebBans = (): Promise<{ items: WebBan[] }> => get('/web-bans');
export const deleteWebBan = (ip: string): Promise<{ ip: string }> =>
	del(`/web-bans/${encodeURIComponent(ip)}`);

export const getUpdateCheck = (): Promise<UpdateCheck> => get('/update/check');

/** One recorded backup run from `GET /api/v1/backups` (`kv` JSON). */
export interface BackupLastRun {
	/** Unix seconds when the run finished. */
	at: number | string;
	result?: string;
	file?: string;
	code?: string;
}

/** `GET /api/v1/backups` (system_routes.rs). */
export interface BackupStatus {
	enabled: boolean;
	directory: string;
	retention_count: number;
	files: number;
	last_run: BackupLastRun | null;
	next_run: string | null;
}

/** `PUT /api/v1/backups/settings` response. */
export interface BackupSettingsResult {
	version: number;
	enabled: boolean;
	retention_count: number;
}

export const getBackups = (): Promise<BackupStatus> => get('/backups');

export const putBackupSettings = (
	body: { enabled: boolean; retention_count: number },
	options?: { ifMatch?: string },
): Promise<BackupSettingsResult> => put('/backups/settings', { body, ifMatch: options?.ifMatch });
