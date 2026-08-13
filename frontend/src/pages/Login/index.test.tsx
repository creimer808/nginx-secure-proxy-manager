import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { useHealth } = vi.hoisted(() => ({ useHealth: vi.fn() }));

vi.mock("src/hooks", () => ({ useHealth }));
vi.mock("src/context", () => ({
	useAuthState: () => ({
		twoFactorChallenge: false,
		login: vi.fn(),
		verifyTwoFactor: vi.fn(),
		cancelTwoFactor: vi.fn(),
	}),
}));
vi.mock("src/components", () => ({
	Button: ({ children }: { children: any }) => <button type="button">{children}</button>,
	LocalePicker: () => <div />,
	Page: ({ children }: { children: any }) => <main>{children}</main>,
	ThemeSwitcher: () => <div />,
}));
vi.mock("src/locale", () => ({
	intl: { formatMessage: ({ id }: { id: string }) => id },
	T: ({ id, data }: { id: string; data?: { version?: string } }) => (
		<>{data?.version ? `${id}:${data.version}` : id}</>
	),
}));

const Login = (await import("./index")).default;

describe("Login version identity", () => {
	afterEach(() => cleanup());

	it("renders separate release links for the app and upstream compatibility baseline", () => {
		useHealth.mockReturnValue({ data: { appVersion: "0.1.2", upstreamVersion: "2.15.1" } });
		render(<Login />);

		expect(screen.getByRole("link", { name: "version.app:0.1.2" })).toHaveAttribute(
			"href",
			"https://github.com/creimer808/nginx-proxy-manager/releases/tag/v0.1.2",
		);
		expect(screen.getByRole("link", { name: "version.upstream:2.15.1" })).toHaveAttribute(
			"href",
			"https://github.com/NginxProxyManager/nginx-proxy-manager/releases/tag/v2.15.1",
		);
	});
});
