import { useQuery } from "@tanstack/react-query";
import { getSecurityEvent, getSecurityEvents, getSecurityFindings, getSecurityLogFiles, getSecurityLogLines, getSecurityOverview, getSecurityRules, getSecuritySettings } from "src/api/backend";
import type { SecurityEventFilters, SecurityLogKind, SecurityLogTarget, SecurityRange } from "src/api/backend";

export const useSecurityOverview = (range: SecurityRange, accessListId?: number) => useQuery({ queryKey: ["security", "overview", range, accessListId ?? null], queryFn: ({ signal }) => getSecurityOverview(range, accessListId, signal) });
export const useSecurityFindings = (range: SecurityRange, accessListId?: number) => useQuery({ queryKey: ["security", "findings", range, accessListId ?? null], queryFn: ({ signal }) => getSecurityFindings(range, accessListId, signal) });
export const useSecurityEvents = (filters: SecurityEventFilters, enabled = true) => useQuery({ queryKey: ["security", "events", filters], queryFn: ({ signal }) => getSecurityEvents(filters, signal), enabled });
export const useSecurityEvent = (eventId: string | null) => useQuery({ queryKey: ["security", "event", eventId], queryFn: ({ signal }) => getSecurityEvent(eventId as string, signal), enabled: Boolean(eventId) });
export const useSecurityRules = (range: SecurityRange) => useQuery({ queryKey: ["security", "rules", range], queryFn: ({ signal }) => getSecurityRules(range, signal) });
export const useSecurityLogFiles = (target: SecurityLogTarget, kind: SecurityLogKind, proxyHostId?: number) => useQuery({ queryKey: ["security", "log-files", target, kind, proxyHostId], queryFn: ({ signal }) => getSecurityLogFiles(target, kind, proxyHostId, signal), enabled: target === "global" || Boolean(proxyHostId) });
export const useSecurityLogs = (params: { target: SecurityLogTarget; kind: SecurityLogKind; proxyHostId?: number; rotation?: string; cursor?: string; direction?: "forward" | "backward"; limit?: number; query?: string }, enabled = true) => useQuery({ queryKey: ["security", "logs", params], queryFn: ({ signal }) => getSecurityLogLines(params, signal), enabled: enabled && (params.target === "global" || Boolean(params.proxyHostId)) && Boolean(params.rotation) });
export const useSecuritySettings = (enabled = true) => useQuery({ queryKey: ["security", "settings"], queryFn: ({ signal }) => getSecuritySettings(signal), enabled });
