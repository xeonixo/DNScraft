import { get, post, put } from './client';

/** One webhook channel from `GET /api/v1/notifications`. */
export interface NotificationChannel {
	id: string;
	type: 'webhook';
	enabled: boolean;
	host: string | null;
	has_secret: boolean;
	events: string[];
}

export interface NotificationsData {
	channels: NotificationChannel[];
	allowed_hosts: string[];
	allow_private_destinations: boolean;
	event_catalog: string[];
}

/** Body of `PUT /api/v1/notifications` (URL and secret are write-only). */
export interface NotificationsPutBody {
	allowed_hosts: string[];
	allow_private_destinations?: boolean;
	channels: Array<{
		id: string;
		type: 'webhook';
		enabled: boolean;
		url?: string;
		secret?: string | null;
		events: string[];
	}>;
}

export interface NotificationsPutResult {
	config_version: number;
}

export interface NotificationTestResult {
	channel_id: string;
	delivered: boolean;
	status?: number;
	latency_ms?: number;
	code?: string;
	reason?: string;
}

export const getNotifications = (): Promise<NotificationsData> =>
	get<NotificationsData>('/notifications');

export const putNotifications = (
	body: NotificationsPutBody,
	options?: { ifMatch?: string },
): Promise<NotificationsPutResult> =>
	put<NotificationsPutResult>('/notifications', { body, ifMatch: options?.ifMatch });

export const testNotification = (channelId: string): Promise<NotificationTestResult> =>
	post<NotificationTestResult>('/notifications/test', { body: { channel_id: channelId } });
