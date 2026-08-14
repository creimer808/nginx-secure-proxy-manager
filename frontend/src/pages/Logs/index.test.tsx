import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import EasyModal from "ez-modal-react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const event = {
	id: 1,
	eventId: "abcdefghijklmnop",
	occurredAtMs: 1_786_550_400_000,
	proxyHostId: 7,
	hostDomainSnapshot: "example.test",
	sourceKind: "security_access",
	eventType: "http_status",
	severity: "medium",
	ruleId: null,
	clientIp: "2001:db8::1",
	method: "GET",
	requestUri: "/a?token=secret",
	userAgent: "curl/8.0",
	status: 403,
	requestTimeMs: 1,
};
const captured = vi.hoisted(() => ({ filters: null as null | Record<string, unknown> }));
vi.mock("src/hooks", () => ({
	useNoReferrer: () => undefined,
	useUser: () => ({ data: { roles: ["admin"], permissions: { proxyHosts: "view" } }, isLoading: false }),
	useProxyHosts: () => ({ data: [{ id: 7, domainNames: ["example.test"] }] }),
	useSecurityEvents: (filters: Record<string, unknown>) => {
		captured.filters = filters;
		return {
			data: { items: [event], nextCursor: "next" },
			isLoading: false,
			isError: false,
			isFetching: false,
			refetch: vi.fn(),
		};
	},
	useSecurityEvent: () => ({ data: undefined, isLoading: false, isError: false }),
	useSecurityLogFiles: () => ({
		data: [{ rotation: "current", available: true, compressed: false }],
		isLoading: false,
		isError: false,
	}),
	useSecurityLogs: () => ({
		data: {
			lines: [{ offset: 0, line: "long request token=secret" }],
			partial: true,
			nextCursor: "next",
			previousCursor: null,
			scanLimitBytes: 1,
		},
		isLoading: false,
		isError: false,
	}),
}));
const Logs = (await import("./index")).default;

const Here = () => {
	const location = useLocation();
	return <span data-testid="location">{location.search}</span>;
};
const renderPage = (entry = "/logs") =>
	render(
		<QueryClientProvider client={new QueryClient()}>
			<MemoryRouter initialEntries={[entry]}>
				<EasyModal.Provider>
					<Here />
					<Logs />
				</EasyModal.Provider>
			</MemoryRouter>
		</QueryClientProvider>,
	);
const search = () => new URLSearchParams(screen.getByTestId("location").textContent ?? "");

describe("Logs page", () => {
	afterEach(() => {
		cleanup();
		captured.filters = null;
	});

	it("materialises a preset range into explicit bounds so the query key stops moving", () => {
		renderPage();
		const params = search();
		expect(params.get("range")).toBe("24h");
		const from = Number(params.get("from"));
		const to = Number(params.get("to"));
		expect(to - from).toBe(86400000);
		expect(captured.filters).toMatchObject({ from: String(from), to: String(to) });
	});

	it("keeps metadata search out of the URL and renders event details as text", () => {
		renderPage("/logs?tab=events&status=403");
		fireEvent.change(screen.getByLabelText("Search URI, user agent, or referrer"), {
			target: { value: "token=secret" },
		});
		expect(search().toString()).not.toContain("token");
		expect(captured.filters).toMatchObject({ query: "token=secret" });
		fireEvent.click(screen.getByRole("button", { name: /View Details: \/a\?token=secret/ }));
		expect(screen.getAllByText("/a?token=secret").length).toBeGreaterThan(1);
	});

	it("removes a single filter from its chip and clears the rest in one action", () => {
		renderPage("/logs?tab=events&status=403&clientIp=2001:db8::1");
		fireEvent.click(screen.getByRole("button", { name: "Remove filter: 403" }));
		expect(search().get("status")).toBeNull();
		expect(search().get("clientIp")).toBe("2001:db8::1");
		fireEvent.click(screen.getByRole("button", { name: "Clear all" }));
		expect(search().get("clientIp")).toBeNull();
	});

	it("asks for operational records only when the toggle is on", () => {
		renderPage();
		expect(captured.filters?.includeOperational).toBeUndefined();
		fireEvent.click(screen.getByLabelText("Include operational events"));
		expect(search().get("includeOperational")).toBe("true");
		expect(captured.filters).toMatchObject({ includeOperational: "true" });
	});

	it("shows raw-log selection guidance before a host is chosen, then partial results", () => {
		renderPage("/logs?tab=raw");
		expect(screen.getByText("Select a proxy host to browse its logs.")).toBeInTheDocument();
		fireEvent.change(screen.getByLabelText("Proxy host"), { target: { value: "7" } });
		expect(screen.getByText("Results are partial because the bounded scan limit was reached.")).toBeInTheDocument();
	});
});
