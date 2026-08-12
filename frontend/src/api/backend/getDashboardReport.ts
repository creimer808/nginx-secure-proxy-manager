import * as api from "./base";
import type { DashboardRange, DashboardReport } from "./responseTypes";

/**
 * Fetch the Security & Traffic dashboard report. An optional AbortSignal lets
 * React Query cancel stale requests when the range changes.
 */
export async function getDashboardReport(
	range: DashboardRange,
	signal?: AbortSignal,
): Promise<DashboardReport> {
	const abortController = new AbortController();
	if (signal) {
		if (signal.aborted) {
			abortController.abort();
		} else {
			signal.addEventListener("abort", () => abortController.abort(), { once: true });
		}
	}
	return await api.get({ url: "/reports/dashboard", params: { range } }, abortController);
}
