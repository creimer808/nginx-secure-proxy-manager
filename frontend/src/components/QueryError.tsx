import { IconRefresh } from "@tabler/icons-react";
import type { ReactNode } from "react";
import { T } from "src/locale";

interface QueryErrorProps {
	message?: ReactNode;
	detail?: string;
	onRetry: () => void;
}

/** A failed read with the one action that can fix it. */
export const QueryError = ({ message, detail, onRetry }: QueryErrorProps) => (
	<div className="alert alert-danger" role="alert">
		{message ?? <T id="security.error" />} {detail}{" "}
		<button type="button" className="btn btn-sm btn-outline-danger" onClick={onRetry}>
			<IconRefresh aria-hidden="true" /> <T id="dashboard.metrics.error-retry" />
		</button>
	</div>
);
