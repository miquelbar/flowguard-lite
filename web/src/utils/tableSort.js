function normalizeCellText(cell) {
    return (cell?.textContent || "").replace(/\s+/g, " ").trim();
}

function parseSortValue(text) {
    if (!text || text === "-" || text === "—") {
        return { type: "empty", value: "" };
    }

    const timestamp = Date.parse(text);
    if (Number.isFinite(timestamp) && /[:/-]|\b(?:am|pm)\b/i.test(text)) {
        return { type: "number", value: timestamp };
    }

    const numeric = Number(text.replace(/,/g, "").replace(/%$/, ""));
    if (Number.isFinite(numeric) && /^-?[\d,.]+%?$/.test(text)) {
        return { type: "number", value: numeric };
    }

    return { type: "text", value: text.toLowerCase() };
}

function compareValues(a, b, direction) {
    const multiplier = direction === "asc" ? 1 : -1;
    if (a.type === "empty" && b.type !== "empty") return 1;
    if (b.type === "empty" && a.type !== "empty") return -1;
    if (a.type === "number" && b.type === "number") {
        return (a.value - b.value) * multiplier;
    }
    return String(a.value).localeCompare(String(b.value), undefined, {
        numeric: true,
        sensitivity: "base"
    }) * multiplier;
}

function defaultDirectionForColumn(rows, index) {
    const values = rows
        .map(row => parseSortValue(normalizeCellText(row.cells[index])))
        .filter(value => value.type !== "empty");
    if (values.some(value => value.type === "number")) return "desc";
    return "asc";
}

function syncIndicators(table, activeIndex, direction) {
    table.querySelectorAll("thead th").forEach((th, index) => {
        const button = th.querySelector(".sortable-th[data-table-sort]");
        const active = index === activeIndex;
        th.setAttribute("aria-sort", active ? (direction === "asc" ? "ascending" : "descending") : "none");
        if (!button) return;
        button.classList.toggle("active", active);
        const indicator = button.querySelector(".sort-indicator");
        if (indicator) indicator.textContent = active ? (direction === "asc" ? "▲" : "▼") : "";
    });
}

function sortTable(table, columnIndex, direction) {
    const tbody = table.tBodies[0];
    if (!tbody) return;
    const rows = Array.from(tbody.rows);
    const sortableRows = rows.filter(row => row.cells.length > columnIndex && !row.querySelector("td[colspan]"));
    const pinnedRows = rows.filter(row => !sortableRows.includes(row));

    sortableRows.sort((left, right) => {
        const a = parseSortValue(normalizeCellText(left.cells[columnIndex]));
        const b = parseSortValue(normalizeCellText(right.cells[columnIndex]));
        return compareValues(a, b, direction);
    });

    tbody.replaceChildren(...sortableRows, ...pinnedRows);
    table.dataset.sortIndex = String(columnIndex);
    table.dataset.sortDirection = direction;
    syncIndicators(table, columnIndex, direction);
}

function shouldSkipHeader(th) {
    if (th.colSpan && th.colSpan > 1) return true;
    if (th.querySelector("[data-flow-sort]")) return true;
    const label = normalizeCellText(th).toLowerCase();
    return label === "" || label === "action" || label === "actions" || label === "select";
}

export function enhanceSortableTables(root = document) {
    root.querySelectorAll("table").forEach(table => {
        const tbody = table.tBodies[0];
        const headerRow = table.tHead?.rows[0];
        if (!tbody || !headerRow) return;

        Array.from(headerRow.cells).forEach((th, index) => {
            if (shouldSkipHeader(th)) return;
            if (!th.dataset.sortEnhanced) {
                const label = normalizeCellText(th);
                const alignRight = th.classList.contains("text-right");
                th.textContent = "";
                const button = document.createElement("button");
                button.type = "button";
                button.className = `sortable-th${alignRight ? " align-right" : ""}`;
                button.dataset.tableSort = String(index);
                button.append(document.createTextNode(label));
                const indicator = document.createElement("span");
                indicator.className = "sort-indicator";
                button.append(indicator);
                button.addEventListener("click", () => {
                    const currentIndex = Number(table.dataset.sortIndex);
                    const currentDirection = table.dataset.sortDirection || "";
                    const sameColumn = currentIndex === index;
                    const direction = sameColumn
                        ? (currentDirection === "asc" ? "desc" : "asc")
                        : defaultDirectionForColumn(Array.from(tbody.rows), index);
                    sortTable(table, index, direction);
                });
                th.append(button);
                th.dataset.sortEnhanced = "true";
            }
        });

        if (table.dataset.sortIndex) {
            sortTable(table, Number(table.dataset.sortIndex), table.dataset.sortDirection || "asc");
        } else {
            syncIndicators(table, -1, "asc");
        }
    });
}
