import { useState } from "react";
import { Link } from "react-router-dom";
import type { SecurityRange } from "src/api/backend";
import { Loading, QueryError, RangeSelector } from "src/components";
import { useSecurityRules } from "src/hooks";
import { T } from "src/locale";
import { formatNumber } from "src/modules/Format";

/**
 * What each built-in rule does, and whether it has ever matched. `block` rules
 * are the signatures inherited from upstream and return 403 on hosts with Block
 * Common Exploits enabled; `detect` rules only attribute, and never change a
 * response. That distinction is the whole reason a host can now see attacks it
 * has chosen not to block, so it is stated per rule rather than in prose.
 */
function RuleCatalog() {
	const [range, setRange] = useState<SecurityRange>("24h");
	const { data, isLoading, isError, refetch } = useSecurityRules(range);
	return (
		<section aria-labelledby="security-rules-heading">
			<div className="d-flex justify-content-between align-items-center gap-2 flex-wrap">
				<h3 id="security-rules-heading" className="mb-0">
					<T id="security.rule-catalog" />
				</h3>
				<RangeSelector value={range} onChange={setRange} />
			</div>
			<p className="text-secondary mt-2">
				<T id="security.rule-catalog-note" />
			</p>
			{isLoading ? (
				<Loading noLogo />
			) : isError || !data ? (
				<QueryError onRetry={() => refetch()} />
			) : (
				<div className="card">
					<div className="table-responsive">
						<table className="table table-sm table-vcenter card-table">
							<thead>
								<tr>
									<th scope="col">
										<T id="security.rule" />
									</th>
									<th scope="col">
										<T id="security.rule-category" />
									</th>
									<th scope="col">
										<T id="security.rule-action" />
									</th>
									<th scope="col">
										<T id="security.description-column" />
									</th>
									<th scope="col" className="text-end">
										<T id="security.count" />
									</th>
								</tr>
							</thead>
							<tbody>
								{data.map((rule) => (
									<tr key={rule.id}>
										<td className="font-monospace">{rule.id}</td>
										<td>{rule.category}</td>
										<td>
											<span
												className={`badge ${rule.action === "block" ? "bg-red-lt" : "bg-blue-lt"}`}
											>
												<T id={`security.rule-action.${rule.action}`} />
											</span>
										</td>
										<td>{rule.description}</td>
										<td className="text-end">
											{rule.count ? (
												<Link
													to={`/logs?tab=events&range=${range}&ruleId=${encodeURIComponent(rule.id)}`}
												>
													{formatNumber(rule.count)}
												</Link>
											) : (
												formatNumber(0)
											)}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</div>
			)}
		</section>
	);
}

export default RuleCatalog;
