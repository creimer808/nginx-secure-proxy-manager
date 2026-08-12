import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DashboardReport } from "src/api/backend";

// Mock the API layer so the component can be tested in isolation.
vi.mock("src/api/backend", async () => {
	const actual = await vi.importActual<typeof import("src/api/backend")>("src/api/backend");
	const getDashboardReport = vi.fn();
	return { ...actual, getDashboardReport };
});

const { getDashboardReport } = await import("src/api/backend");
// vi.mocked() restores the Mock typing needed for mockResolvedValue / toHaveBeenCalledWith.
const mockedGetDashboardReport = vi.mocked(getDashboardReport);
const SecurityTrafficDashboard = (await import("./SecurityTrafficDashboard")).default;

const sampleReport = (): DashboardReport => ({
	range: "24h",
	generatedAt: 1786550400,
	collection: { enabled: true },
	posture: {
		enabled: 12,
		disabled: 1,
		certificateConfigured: 11,
		forcedHttps: 10,
		effectiveHsts: 8,
		exploitRulesEnabled: 9,
		accessControlled: 4,
		certificatesExpired: 0,
		certificatesExpiring: 2,
	},
	traffic: {
		requests: 185430,
		bytesSent: 924728233,
		status1xx: 0,
		status2xx: 179240,
		status3xx: 3210,
		status4xx: 2710,
		status5xx: 270,
	},
	series: [
		{
			bucketStart: 1786544000,
			requestCount: 1200,
			status1xx: 0,
			status2xx: 1100,
			status3xx: 40,
			status4xx: 50,
			status5xx: 10,
		},
	],
	topHosts: [
		{
			id: 1,
			domain: "example.com",
			requestCount: 90000,
			bytesSent: 400000000,
			status4xx: 1000,
			status5xx: 100,
		},
	],
	topSources: {
		approximate: true,
		items: [
			{
				clientIp: "203.0.113.25",
				proxyHostId: 1,
				domain: "example.com",
				status4xx: 40,
				status5xx: 2,
				observedCount: 42,
			},
		],
	},
});

const renderWithClient = () => {
	const queryClient = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	return {
		queryClient,
		...render(
			<QueryClientProvider client={queryClient}>
				<SecurityTrafficDashboard />
			</QueryClientProvider>,
		),
	};
};

describe("SecurityTrafficDashboard", () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("renders an initial loading state while the request is unresolved", () => {
		mockedGetDashboardReport.mockImplementation(() => new Promise(() => {}));
		renderWithClient();

		expect(screen.getByText("Loading…")).toBeInTheDocument();
	});

	it("renders summary, posture, and textual status alternatives", async () => {
		mockedGetDashboardReport.mockResolvedValue(sampleReport());
		renderWithClient();

		expect(mockedGetDashboardReport).toHaveBeenCalledWith("24h", expect.anything());
		await waitFor(() => {
			expect(screen.getAllByText("185,430").length).toBeGreaterThan(0);
		});
		// Posture counts render (not only color).
		expect(screen.getAllByText("12").length).toBeGreaterThan(0);
		expect(screen.getAllByText("example.com").length).toBeGreaterThan(0);
		expect(screen.getByText("1xx informational")).toBeInTheDocument();
		expect(screen.getByText("2xx success")).toBeInTheDocument();
		expect(screen.getByText("4xx client error")).toBeInTheDocument();
	});

	it("renders the approximate/privacy note for top observed client IPs", async () => {
		mockedGetDashboardReport.mockResolvedValue(sampleReport());
		renderWithClient();

		await waitFor(() => {
			expect(screen.getAllByText("203.0.113.25").length).toBeGreaterThan(0);
		});
		// The privacy note is present and distinct from the section heading.
		expect(screen.getByText(/approximate observations/i)).toBeInTheDocument();
	});

	it("retries after an error", async () => {
		mockedGetDashboardReport.mockRejectedValueOnce(new Error("boom")).mockResolvedValueOnce(sampleReport());
		renderWithClient();

		await waitFor(() => {
			expect(screen.getByText("Could not load security & traffic metrics.")).toBeInTheDocument();
		});
		fireEvent.click(screen.getByText("Retry"));
		await waitFor(() => {
			expect(mockedGetDashboardReport).toHaveBeenCalledTimes(2);
			expect(screen.getAllByText("185,430").length).toBeGreaterThan(0);
		});
	});

	it("switches the range and refetches with the new range", async () => {
		mockedGetDashboardReport.mockResolvedValue(sampleReport());
		renderWithClient();

		await waitFor(() => {
			expect(screen.getAllByText("185,430").length).toBeGreaterThan(0);
		});

		const sevenDayButton = screen.getByText("7 days").closest("button");
		expect(sevenDayButton).not.toBeNull();
		fireEvent.click(sevenDayButton as HTMLElement);

		await waitFor(() => {
			expect(mockedGetDashboardReport).toHaveBeenLastCalledWith("7d", expect.anything());
		});
	});

	it("shows the no-traffic empty state", async () => {
		const report = sampleReport();
		report.traffic = {
			requests: 0,
			bytesSent: 0,
			status1xx: 0,
			status2xx: 0,
			status3xx: 0,
			status4xx: 0,
			status5xx: 0,
		};
		report.series = [];
		report.topHosts = [];
		report.topSources.items = [];
		mockedGetDashboardReport.mockResolvedValue(report);
		renderWithClient();

		await waitFor(() => {
			expect(screen.getByText(/No traffic has been collected yet/i)).toBeInTheDocument();
			expect(screen.getByText("0 B")).toBeInTheDocument();
		});
	});

	it("shows the disabled note when collection is disabled", async () => {
		const disabled = { ...sampleReport(), collection: { enabled: false } };
		mockedGetDashboardReport.mockResolvedValue(disabled);
		renderWithClient();

		await waitFor(() => {
			expect(screen.getByText(/Traffic metrics collection is disabled/i)).toBeInTheDocument();
			expect(screen.getByText("Security posture")).toBeInTheDocument();
		});
	});
});
