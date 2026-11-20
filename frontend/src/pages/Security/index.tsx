import { IconShieldSearch } from "@tabler/icons-react";
import { Navigate, useSearchParams } from "react-router-dom";
import { HasPermission } from "src/components";
import { useNoReferrer } from "src/hooks";
import { T } from "src/locale";
import { PROXY_HOSTS, VIEW } from "src/modules/Permissions";
import Configuration from "./Configuration";
import Overview from "./Overview";
import RuleCatalog from "./RuleCatalog";
import styles from "./Security.module.css";

type Tab = "overview" | "rules" | "settings";
const tabs: { value: Tab; label: string }[] = [
	{ value: "overview", label: "security.overview" },
	{ value: "rules", label: "security.rule-catalog" },
	{ value: "settings", label: "security.configuration" },
];
/**
 * Event search and raw log browsing moved to /logs. Links from before the split
 * -- bookmarks, and the deep links the old overview tiles wrote -- carry their
 * filters with them rather than landing on a page that no longer has the tab.
 */
const MOVED_TABS = new Set(["events", "logs"]);

function Security() {
	const [params, setParams] = useSearchParams();
	useNoReferrer();
	const selectedTab = params.get("tab");
	if (selectedTab && MOVED_TABS.has(selectedTab)) {
		const moved = new URLSearchParams(params);
		moved.set("tab", selectedTab === "logs" ? "raw" : "events");
		return <Navigate to={`/logs?${moved.toString()}`} replace />;
	}
	const tab: Tab = selectedTab && tabs.some((item) => item.value === selectedTab) ? (selectedTab as Tab) : "overview";
	const selectTab = (value: Tab) =>
		setParams((current) => {
			const next = new URLSearchParams(current);
			next.set("tab", value);
			return next;
		});
	return (
		<HasPermission section={PROXY_HOSTS} permission={VIEW} pageLoading loadingNoLogo>
			<main className={styles.page} aria-labelledby="security-heading">
				<h2 id="security-heading">
					<IconShieldSearch aria-hidden="true" /> <T id="security.title" />
				</h2>
				<p className="text-secondary">
					<T id="security.description" />
				</p>
				<nav className={styles.tabs} aria-label="Security sections">
					{tabs.map((item) => (
						<button
							type="button"
							key={item.value}
							className={`btn ${tab === item.value ? "btn-primary" : "btn-outline-primary"}`}
							aria-current={tab === item.value ? "page" : undefined}
							onClick={() => selectTab(item.value)}
						>
							<T id={item.label} />
						</button>
					))}
				</nav>
				{tab === "overview" && <Overview />}
				{tab === "rules" && <RuleCatalog />}
				{tab === "settings" && <Configuration />}
			</main>
		</HasPermission>
	);
}

export default Security;
