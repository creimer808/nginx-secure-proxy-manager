import * as api from "./base";
import type { SecurityEvent, SecurityEventFilters, SecurityEventPage, SecurityFindingReport, SecurityLogFile, SecurityLogKind, SecurityLogPage, SecurityLogTarget, SecurityOverview, SecurityRange, SecurityRule, SecuritySettings } from "./models";

const controller = (signal?: AbortSignal) => {
	const value = new AbortController();
	if (signal) signal.addEventListener("abort", () => value.abort(), { once: true });
	return value;
};

export const getSecurityOverview = async (range: SecurityRange, signal?: AbortSignal): Promise<SecurityOverview> => api.get({ url: "/security/overview", params: { range } }, controller(signal));
export const getSecurityFindings = async (range: SecurityRange, signal?: AbortSignal): Promise<SecurityFindingReport> => api.get({ url: "/security/findings", params: { range } }, controller(signal));
export const getSecurityEvents = async (filters: SecurityEventFilters, signal?: AbortSignal): Promise<SecurityEventPage> => api.get({ url: "/security/events", params: filters as unknown as import("query-string").StringifiableRecord }, controller(signal));
export const getSecurityEvent = async (eventId: string, signal?: AbortSignal): Promise<SecurityEvent> => api.get({ url: `/security/events/${encodeURIComponent(eventId)}` }, controller(signal));
export const getSecurityRules = async (range: SecurityRange, signal?: AbortSignal): Promise<SecurityRule[]> => api.get({ url: "/security/rules", params: { range } }, controller(signal));
export const getSecurityLogFiles = async (target: SecurityLogTarget, kind: SecurityLogKind, proxyHostId?: number, signal?: AbortSignal): Promise<SecurityLogFile[]> => api.get({ url: "/security/log-files", params: { target, kind, proxyHostId } }, controller(signal));
export const getSecurityLogLines = async (params: { target: SecurityLogTarget; kind: SecurityLogKind; proxyHostId?: number; rotation?: string; cursor?: string; direction?: "forward" | "backward"; limit?: number; query?: string }, signal?: AbortSignal): Promise<SecurityLogPage> => api.get({ url: "/security/logs", params }, controller(signal));
export const getSecuritySettings = async (signal?: AbortSignal): Promise<SecuritySettings> => api.get({ url: "/security/settings" }, controller(signal));
export const updateSecuritySettings = async (retentionDays: number, signal?: AbortSignal): Promise<SecuritySettings> => api.put({ url: "/security/settings", data: { retentionDays } }, controller(signal));
