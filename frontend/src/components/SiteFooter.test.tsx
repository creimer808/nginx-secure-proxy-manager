import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { useHealth, useCheckVersion } = vi.hoisted(() => ({ useHealth: vi.fn(), useCheckVersion: vi.fn() }));

vi.mock("src/hooks", () => ({ useHealth, useCheckVersion }));
vi.mock("src/locale", () => ({
	intl: { formatMessage: ({ id }: { id: string }, data: { version: string }) => `${id}:${data.version}` },
	T: ({ id, data }: { id: string; data?: { version?: string } }) => (
		<>{data?.version ? `${id}:${data.version}` : id}</>
	),
}));

const { SiteFooter } = await import("./SiteFooter");

describe("SiteFooter version identity", () => {
	afterEach(() => cleanup());

	it("links both release versions and labels an upstream update", () => {
		useHealth.mockReturnValue({ data: { appVersion: "0.1.0", upstreamVersion: "2.15.1" } });
		useCheckVersion.mockReturnValue({ data: { updateAvailable: true, latest: "v2.16.0" } });

		render(<SiteFooter />);

		expect(screen.getByRole("link", { name: "version.app:0.1.0" })).toHaveAttribute(
			"href",
			"https://github.com/creimer808/nginx-proxy-manager/releases/tag/v0.1.0",
		);
		expect(screen.getByRole("link", { name: "version.upstream:2.15.1" })).toHaveAttribute(
			"href",
			"https://github.com/NginxProxyManager/nginx-proxy-manager/releases/tag/v2.15.1",
		);
		expect(screen.getByRole("link", { name: "version.upstream-update:v2.16.0" })).toHaveAttribute(
			"href",
			"https://github.com/NginxProxyManager/nginx-proxy-manager/releases/tag/v2.16.0",
		);
	});
});
