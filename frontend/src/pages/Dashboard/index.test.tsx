import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("src/hooks", () => ({
	useHostReport: () => ({ data: { proxy: 0, redirection: 0, stream: 0, dead: 0 } }),
	useUser: () => ({
		data: {
			permissions: {
				proxyHosts: "hidden",
				redirectionHosts: "hidden",
				deadHosts: "hidden",
				streams: "hidden",
			},
			roles: ["user"],
		},
		isLoading: false,
	}),
}));

const Dashboard = (await import("./index")).default;

describe("Dashboard permissions", () => {
	afterEach(() => cleanup());

	it("does not render the Security & Traffic panel without proxy-host view permission", () => {
		render(
			<MemoryRouter>
				<Dashboard />
			</MemoryRouter>,
		);

		expect(screen.queryByText("Security & Traffic")).not.toBeInTheDocument();
	});
});
