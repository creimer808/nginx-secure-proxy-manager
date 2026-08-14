import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { hasPermission, PROXY_HOSTS, VIEW } from "src/modules/Permissions";

const upgraded = {
	lastRunOn: null,
	hostsTotal: 3,
	hostsUpgraded: 3,
	hostsSkipped: 0,
	hostsPending: 0,
	reloadDeferred: false,
	lastErrorSummary: null,
};
const finding = {
	id: "f1",
	type: "path_scanning",
	severity: "high",
	operational: false,
	firstSeen: 1_786_550_400_000,
	lastSeen: 1_786_554_000_000,
	evidenceCount: 412,
	subject: { clientIp: "203.0.113.9", proxyHostId: null, hostDomain: null },
	metrics: { distinctUris: 412, distinctHosts: 3 },
	filter: { clientIp: "203.0.113.9", status: 404, from: 1, to: 2 },
};
const hooks = vi.hoisted(() => ({ roles: ["admin"], nginxUpgrade: null as null | Record<string, unknown> }));
vi.mock("src/hooks", () => ({
	useNoReferrer: () => undefined,
	useUser: () => ({ data: { roles: hooks.roles, permissions: { proxyHosts: "view" } }, isLoading: false }),
	useProxyHosts: () => ({ data: [{ id: 7, domainNames: ["example.test"] }] }),
	useSecurityOverview: () => ({
		data: {
			range: "24h",
			totalEvents: 2,
			exploitRuleMatches: 1,
			operationalEvents: 0,
			nginxErrors: 0,
			distinctSources: 5,
			distinctHosts: 2,
			statuses: { "401": 0, "403": 1, "404": 0, "429": 0, "5xx": 0 },
			timeline: [],
			topRules: [{ ruleId: "path.dotenv", count: 4 }],
			topSources: [{ clientIp: "203.0.113.9", count: 9 }],
			topHosts: [],
			topStatuses: [],
			topMethods: [],
			collector: { available: true, lagMs: 1200 },
		},
		isLoading: false,
		isError: false,
		refetch: vi.fn(),
	}),
	useSecurityFindings: () => ({
		data: {
			range: "24h",
			generatedAt: 0,
			window: { from: 1, to: 2 },
			counts: { low: 0, medium: 0, high: 1, critical: 0 },
			truncated: false,
			findings: [finding],
		},
		isLoading: false,
		isError: false,
		refetch: vi.fn(),
	}),
	useSecurityRules: () => ({
		data: [
			{
				id: "sql.union-select",
				category: "sql",
				action: "block",
				description: "Built-in SQL union/select signature",
				rulesetVersion: "2026-08-14",
				count: 0,
			},
			{
				id: "path.dotenv",
				category: "path-probe",
				action: "detect",
				description: "Request for a .env environment file",
				rulesetVersion: "2026-08-14",
				count: 12,
			},
		],
		isLoading: false,
		isError: false,
		refetch: vi.fn(),
	}),
	useSecuritySettings: () => ({ data: { retentionDays: 30, nginxUpgrade: hooks.nginxUpgrade } }),
}));
vi.mock("src/api/backend", async (original) => ({
	...(await original<typeof import("src/api/backend")>()),
	updateSecuritySettings: vi.fn(),
}));
const Security = (await import("./index")).default;

const Here = () => {
	const location = useLocation();
	return <span data-testid="location">{`${location.pathname}${location.search}`}</span>;
};
const renderPage = (entry = "/security") =>
	render(
		<QueryClientProvider client={new QueryClient()}>
			<MemoryRouter initialEntries={[entry]}>
				<Here />
				<Routes>
					<Route path="/security" element={<Security />} />
					<Route path="/logs" element={<span>logs page</span>} />
				</Routes>
			</MemoryRouter>
		</QueryClientProvider>,
	);

describe("Security page", () => {
	afterEach(() => {
		cleanup();
		hooks.roles = ["admin"];
		hooks.nginxUpgrade = null;
	});

	it("denies page navigation when proxy host view permission is hidden", () => {
		expect(
			hasPermission(
				PROXY_HOSTS,
				VIEW,
				{
					visibility: "user",
					proxyHosts: "hidden",
					redirectionHosts: "hidden",
					deadHosts: "hidden",
					streams: "hidden",
					accessLists: "hidden",
					certificates: "hidden",
				},
				["user"],
			),
		).toBe(false);
	});

	it("leads with findings and links each one to the events that produced it", () => {
		renderPage();
		expect(screen.getByText("Path scanning")).toBeInTheDocument();
		expect(
			screen.getByText("203.0.113.9 requested 412 distinct missing paths across 3 proxy hosts."),
		).toBeInTheDocument();
		// The evidence link is built from the filter the detector shipped, never
		// reconstructed from the summary text.
		const evidence = screen.getByRole("link", { name: /View evidence/ });
		expect(evidence).toHaveAttribute("href", expect.stringContaining("clientIp=203.0.113.9"));
		expect(evidence).toHaveAttribute("href", expect.stringContaining("status=404"));
	});

	it("keeps healthy collector status to a pill rather than a standing banner", () => {
		renderPage();
		expect(screen.getByText("Available")).toBeInTheDocument();
		expect(screen.queryByText("Collector health")).not.toBeInTheDocument();
	});

	it("redirects the tabs that moved to /logs, carrying their filters", () => {
		renderPage("/security?tab=events&status=403");
		expect(screen.getByText("logs page")).toBeInTheDocument();
		expect(screen.getByTestId("location")).toHaveTextContent("/logs?tab=events&status=403");
	});

	it("names each rule's action so a detect-only rule is not read as a block", () => {
		renderPage("/security?tab=rules");
		expect(screen.getByText("sql.union-select").closest("tr")).toHaveTextContent("Block");
		expect(screen.getByText("path.dotenv").closest("tr")).toHaveTextContent("Detect");
	});

	it("labels the retention save control instead of rendering its message id", () => {
		renderPage("/security?tab=settings");
		expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
		expect(screen.getByLabelText("Detailed event retention (days)")).toHaveValue(30);
		expect(screen.queryByText("action.save")).not.toBeInTheDocument();
	});

	it("reports whether Nginx actually received the security logging configuration", () => {
		hooks.nginxUpgrade = {
			...upgraded,
			hostsUpgraded: 2,
			hostsSkipped: 1,
			reloadDeferred: true,
			lastErrorSummary: "proxy host 7: missing certificate",
		};
		renderPage("/security?tab=settings");
		expect(screen.getByText(/not active on every enabled proxy host/)).toBeInTheDocument();
		expect(screen.getByText("proxy host 7: missing certificate")).toBeInTheDocument();
		cleanup();
		hooks.nginxUpgrade = upgraded;
		renderPage("/security?tab=settings");
		expect(screen.getByText(/is active on every enabled proxy host/)).toBeInTheDocument();
	});
});
