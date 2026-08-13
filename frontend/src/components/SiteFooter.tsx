import { useCheckVersion, useHealth } from "src/hooks";
import { intl, T } from "src/locale";

export function SiteFooter() {
	const health = useHealth();
	const { data: versionData } = useCheckVersion();
	const versions = health.data ? { app: health.data.appVersion, upstream: health.data.upstreamVersion } : null;

	return (
		<footer className="footer d-print-none py-3">
			<div className="container-xl">
				<div className="row text-center align-items-center flex-row-reverse">
					<div className="col-lg-auto ms-lg-auto">
						<ul className="list-inline list-inline-dots mb-0">
							<li className="list-inline-item">
								<a
									href="https://github.com/creimer808/nginx-proxy-manager"
									target="_blank"
									className="link-secondary"
									rel="noopener noreferrer"
								>
									<T id="footer.nspm-github" />
								</a>
							</li>
							<li className="list-inline-item">
								<a
									href="https://github.com/NginxProxyManager/nginx-proxy-manager"
									target="_blank"
									className="link-secondary"
									rel="noopener noreferrer"
								>
									<T id="footer.upstream-npm" />
								</a>
							</li>
						</ul>
					</div>
					<div className="col-12 col-lg-auto mt-3 mt-lg-0">
						<ul className="list-inline list-inline-dots mb-0">
							<li className="list-inline-item">
								© 2026{" "}
								<a
									href="https://www.cybersec.cam"
									rel="noreferrer"
									target="_blank"
									className="link-secondary"
								>
									CyberSec.Cam
								</a>{" "}
								by{" "}
								<a
									href="https://github.com/creimer808"
									rel="noreferrer"
									target="_blank"
									className="link-secondary"
								>
									creimer808
								</a>
							</li>
							<li className="list-inline-item">
								Theme by{" "}
								<a href="https://tabler.io" rel="noreferrer" target="_blank" className="link-secondary">
									Tabler
								</a>
							</li>
							{versions && (
								<>
									<li className="list-inline-item">
										<a
											href={`https://github.com/creimer808/nginx-proxy-manager/releases/tag/v${versions.app}`}
											className="link-secondary"
											target="_blank"
											rel="noopener noreferrer"
										>
											<T id="version.app" data={{ version: versions.app }} />
										</a>
									</li>
									<li className="list-inline-item">
										<a
											href={`https://github.com/NginxProxyManager/nginx-proxy-manager/releases/tag/v${versions.upstream}`}
											className="link-secondary"
											target="_blank"
											rel="noopener noreferrer"
										>
											<T id="version.upstream" data={{ version: versions.upstream }} />
										</a>
									</li>
								</>
							)}
							{versionData?.updateAvailable && versionData.latest && (
								<li className="list-inline-item">
									<a
										href={`https://github.com/NginxProxyManager/nginx-proxy-manager/releases/tag/${versionData.latest}`}
										className="link-warning fw-bold"
										target="_blank"
										rel="noopener noreferrer"
										title={intl.formatMessage(
											{ id: "version.upstream-update-title" },
											{ version: versionData.latest },
										)}
									>
										<T id="version.upstream-update" data={{ version: versionData.latest }} />
									</a>
								</li>
							)}
						</ul>
					</div>
				</div>
			</div>
		</footer>
	);
}
