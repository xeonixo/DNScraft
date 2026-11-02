import { get } from './client';

/** One row of `GET /api/v1/alerts`. */
export interface AlertItem {
	id: string;
	severity: 'critical' | 'warning' | string;
	module: string;
	params: Record<string, unknown>;
	target_route: string;
}

export interface AlertsData {
	active_count: number;
	items: AlertItem[];
}

/** `GET /api/v1/alerts` — active problems across modules. */
export const getAlerts = (): Promise<AlertsData> => get<AlertsData>('/alerts');
