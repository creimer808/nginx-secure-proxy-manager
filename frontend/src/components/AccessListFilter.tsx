import type { AccessList } from "src/api/backend";
import { useAccessLists } from "src/hooks";
import { intl, T } from "src/locale";

interface AccessListFilterProps {
	value?: number;
	onChange: (accessListId?: number) => void;
}

/**
 * Narrows the security views to hosts protected by one access list. The
 * unfiltered default is its own option so a linked or bookmarked view can be
 * restored to "everywhere" with the same control that narrowed it.
 */
export const AccessListFilter = ({ value, onChange }: AccessListFilterProps) => {
	const { data } = useAccessLists();
	const lists: AccessList[] = data ?? [];
	return (
		<select
			className="form-select form-select-sm w-auto"
			aria-label={intl.formatMessage({ id: "access-list-filter.label" })}
			value={value ?? ""}
			onChange={(event) => onChange(event.target.value ? Number(event.target.value) : undefined)}
		>
			<option value="">
				<T id="access-list-filter.all" />
			</option>
			{lists.map((list) => (
				<option key={list.id} value={list.id}>
					{list.name}
				</option>
			))}
		</select>
	);
};
