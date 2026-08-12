import { useQuery } from "@tanstack/react-query";
import { getDashboardReport } from "src/api/backend";
import type { DashboardRange, DashboardReport } from "src/api/backend";

const useDashboardReport = (range: DashboardRange, options = {}) => {
	return useQuery<DashboardReport, Error>({
		queryKey: ["dashboard-report", range],
		queryFn: ({ signal }) => getDashboardReport(range, signal),
		refetchInterval: 60 * 1000, // refresh every 60 seconds
		refetchOnWindowFocus: false,
		// Keep the previous range's data visible while the next range loads.
		placeholderData: (previousData) => previousData,
		...options,
	});
};

export { useDashboardReport };
