import { useQuery } from "@tanstack/react-query";
import { getSecurityEvent, getSecurityEvents, getSecurityLogFiles, getSecurityLogLines, getSecurityOverview, getSecurityRules, getSecuritySettings } from "src/api/backend";
import type { SecurityEventFilters, SecurityLogKind, SecurityLogTarget, SecurityRange } from "src/api/backend";

export const useSecurityOverview = (range: SecurityRange) => useQuery({ queryKey: ["security", "overview", range], queryFn: ({ signal }) => getSecurityOverview(range, signal) });
export const useSecurityEvents = (filters: SecurityEventFilters) => useQuery({ queryKey: ["security", "events", filters], queryFn: ({ signal }) => getSecurityEvents(filters, signal) });
export const useSecurityEvent = (eventId: string | null) => useQuery({ queryKey: ["security", "event", eventId], queryFn: ({ signal }) => getSecurityEvent(eventId as string, signal), enabled: Boolean(eventId) });
export const useSecurityRules = (range: SecurityRange) => useQuery({ queryKey: ["security", "rules", range], queryFn: ({ signal }) => getSecurityRules(range, signal) });
export const useSecurityLogFiles = (target: SecurityLogTarget, kind: SecurityLogKind, proxyHostId?: number) => useQuery({ queryKey: ["security", "log-files", target, kind, proxyHostId], queryFn: ({ signal }) => getSecurityLogFiles(target, kind, proxyHostId, signal), enabled: target === "global" || Boolean(proxyHostId) });
export const useSecurityLogs = (params: { target: SecurityLogTarget; kind: SecurityLogKind; proxyHostId?: number; rotation?: string; cursor?: string; direction?: "forward" | "backward"; limit?: number; query?: string }, enabled = true) => useQuery({ queryKey: ["security", "logs", params], queryFn: ({ signal }) => getSecurityLogLines(params, signal), enabled: enabled && (params.target === "global" || Boolean(params.proxyHostId)) && Boolean(params.rotation) });
export const useSecuritySettings = (enabled = true) => useQuery({ queryKey: ["security", "settings"], queryFn: ({ signal }) => getSecuritySettings(signal), enabled });
