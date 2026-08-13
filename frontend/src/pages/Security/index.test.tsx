import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { hasPermission, PROXY_HOSTS, VIEW } from "src/modules/Permissions";

const hooks = vi.hoisted(() => ({ roles: ["admin"], permission: "view" }));
vi.mock("src/hooks", () => ({
	useUser: () => ({ data: { roles: hooks.roles, permissions: { proxyHosts: hooks.permission } }, isLoading: false }),
	useProxyHosts: () => ({ data: [{ id: 7, domainNames: ["example.test"] }] }),
	useSecurityOverview: () => ({ data: { range: "24h", totalEvents: 2, exploitRuleMatches: 1, nginxErrors: 0, statuses: { "401": 0, "403": 1, "404": 0, "429": 0, "5xx": 0 }, timeline: [], topRules: [], topSources: [], topHosts: [], topStatuses: [], topMethods: [], collector: { available: true } }, isLoading: false, isError: false, refetch: vi.fn() }),
	useSecurityEvents: () => ({ data: { items: [{ id: 1, eventId: "abcdefghijklmnop", occurredAtMs: 1, proxyHostId: 7, hostDomainSnapshot: "example.test", sourceKind: "security_access", eventType: "http_status", severity: "medium", ruleId: null, clientIp: "2001:db8::1", method: "GET", requestUri: "/a?token=secret", status: 403, requestTimeMs: 1 }], nextCursor: "next" }, isLoading: false, isError: false, isFetching: false, refetch: vi.fn() }),
	useSecurityEvent: () => ({ data: undefined, isLoading: false, isError: false }),
	useSecurityLogFiles: () => ({ data: [{ rotation: "current", available: true, compressed: false }] }),
	useSecurityLogs: () => ({ data: { lines: [{ offset: 0, line: "long request token=secret" }], partial: true, nextCursor: "next", previousCursor: null, scanLimitBytes: 1 }, isLoading: false, isError: false }),
	useSecuritySettings: () => ({ data: { retentionDays: 30 } }),
}));
vi.mock("src/api/backend", async (original) => ({ ...(await original<typeof import("src/api/backend")>()), updateSecuritySettings: vi.fn() }));
const Security = (await import("./index")).default;
const renderPage = (entry = "/security") => render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={[entry]}><Security /></MemoryRouter></QueryClientProvider>);

describe("Security page", () => {
	afterEach(() => { cleanup(); hooks.roles = ["admin"]; hooks.permission = "view"; });
	it("denies page navigation when proxy host view permission is hidden", () => { expect(hasPermission(PROXY_HOSTS, VIEW, { visibility: "user", proxyHosts: "hidden", redirectionHosts: "hidden", deadHosts: "hidden", streams: "hidden", accessLists: "hidden", certificates: "hidden" }, ["user"])).toBe(false); });
	it("keeps metadata search out of structural URL filters and renders details as text", () => { renderPage("/security?tab=events&status=403"); fireEvent.change(screen.getByLabelText("Search URI, user agent, or referrer"), { target: { value: "token=secret" } }); expect(window.location.search).not.toContain("token"); fireEvent.click(screen.getByLabelText("View details for /a?token=secret")); expect(screen.getAllByText("/a?token=secret").length).toBeGreaterThan(1); });
	it("shows raw-log selection guidance, partial results, and admin configuration", () => { renderPage("/security?tab=logs"); expect(screen.getByText("Select a proxy host to browse its logs.")).toBeInTheDocument(); fireEvent.change(screen.getByLabelText("Proxy host"), { target: { value: "7" } }); expect(screen.getByText("Results are partial because the bounded scan limit was reached.")).toBeInTheDocument(); fireEvent.click(screen.getByRole("button", { name: "Configuration" })); expect(screen.getByLabelText("Detailed event retention (days)")).toHaveValue(30); });
});
