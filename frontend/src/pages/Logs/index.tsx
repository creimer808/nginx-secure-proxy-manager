import { IconListSearch } from "@tabler/icons-react";
import { useSearchParams } from "react-router-dom";
import { HasPermission } from "src/components";
import { useNoReferrer } from "src/hooks";
import { T } from "src/locale";
import { PROXY_HOSTS, VIEW } from "src/modules/Permissions";
import Events from "./Events";
import styles from "./Logs.module.css";
import RawLogs from "./RawLogs";

type Tab = "events" | "raw";
const tabs: { value: Tab; label: string }[] = [
	{ value: "events", label: "security.events" },
	{ value: "raw", label: "security.raw-logs" },
];

/**
 * The explorer, split out of /security. Security is now a curated findings
 * page; everything that answers "show me the records themselves" lives here.
 */
function Logs() {
	const [params, setParams] = useSearchParams();
	useNoReferrer();
	const selectedTab = params.get("tab");
	const tab: Tab = selectedTab && tabs.some((item) => item.value === selectedTab) ? (selectedTab as Tab) : "events";
	/** One writer for the query string, so no caller has to remember to clear the cursor. */
	const update = (changes: Record<string, string | null>) =>
		setParams(
			(current) => {
				const next = new URLSearchParams(current);
				for (const [key, value] of Object.entries(changes)) {
					if (value === null || value === "") next.delete(key);
					else next.set(key, value);
				}
				return next;
			},
			{ replace: true },
		);
	return (
		<HasPermission section={PROXY_HOSTS} permission={VIEW} pageLoading loadingNoLogo>
			<main className={styles.page} aria-labelledby="logs-heading">
				<h2 id="logs-heading">
					<IconListSearch aria-hidden="true" /> <T id="logs.title" />
				</h2>
				<p className="text-secondary">
					<T id="logs.description" />
				</p>
				<nav className={styles.tabs} aria-label="Log sections">
					{tabs.map((item) => (
						<button
							type="button"
							key={item.value}
							className={`btn ${tab === item.value ? "btn-primary" : "btn-outline-primary"}`}
							aria-current={tab === item.value ? "page" : undefined}
							onClick={() => update({ tab: item.value })}
						>
							<T id={item.label} />
						</button>
					))}
				</nav>
				{tab === "events" ? <Events params={params} update={update} /> : <RawLogs />}
			</main>
		</HasPermission>
	);
}

export default Logs;
