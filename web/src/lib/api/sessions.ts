import { ApiError, del, get, isRecord } from './client';
import { CLIENT_MALFORMED } from './error-codes';

/** `scope=all` is admin-only. Viewers are limited to their own sessions. */
export type SessionScope = 'own' | 'all';

export interface AuthSession {
	id: string;
	actor_id: string;
	actor_type: string;
	role: string;
	client_label: string | null;
	ip: string | null;
	created_at: string;
	last_seen: string;
	expires_at: string;
	current: boolean;
}

export interface SessionList {
	items: AuthSession[];
	has_more: boolean;
	next_offset: number | null;
}

function text(value: unknown): string | null {
	return typeof value === 'string' ? value : null;
}

function parseSession(value: unknown): AuthSession {
	if (!isRecord(value) || typeof value.id !== 'string') throw new ApiError(0, CLIENT_MALFORMED);
	return {
		id: value.id,
		actor_id: typeof value.actor_id === 'string' ? value.actor_id : '',
		actor_type: typeof value.actor_type === 'string' ? value.actor_type : '',
		role: typeof value.role === 'string' ? value.role : '',
		client_label: text(value.client_label),
		ip: text(value.ip),
		created_at: text(value.created_at) ?? '',
		last_seen: text(value.last_seen) ?? '',
		expires_at: text(value.expires_at) ?? '',
		current: value.current === true,
	};
}

/** `GET /api/v1/auth/sessions`. Default scope is chosen by the caller (own for a viewer, all for an admin). */
export async function listSessions(scope: SessionScope, offset = 0): Promise<SessionList> {
	const params = new URLSearchParams({ scope, offset: String(offset) });
	const data = await get<unknown>(`/auth/sessions?${params}`);
	if (!isRecord(data) || !Array.isArray(data.items)) throw new ApiError(0, CLIENT_MALFORMED);
	return {
		items: data.items.map(parseSession),
		has_more: data.has_more === true,
		next_offset: typeof data.next_offset === 'number' ? data.next_offset : null,
	};
}

/** `DELETE /api/v1/auth/sessions/{id}`. The current session is rejected by the server. */
export const revokeSession = (id: string): Promise<{ id: string; revoked: boolean }> =>
	del(`/auth/sessions/${encodeURIComponent(id)}`);
