/**
 * Appends a token to a space-separated search input if not already present.
 * @param {HTMLInputElement} input
 * @param {string} token
 */
export function appendSearchToken(input, token) {
    if (!input) return;
    const cleanToken = token.trim();
    if (!cleanToken) return;

    const currentVal = input.value.trim();
    if (!currentVal) {
        input.value = cleanToken + " ";
        return;
    }

    const tokens = currentVal.split(/\s+/);
    if (!tokens.includes(cleanToken)) {
        tokens.push(cleanToken);
        input.value = tokens.join(" ") + " ";
    }
}

/**
 * Triggers an 'input' or 'change' event on the given element.
 * @param {HTMLElement} element
 * @param {string} eventName
 */
export function triggerEvent(element, eventName = "input") {
    if (!element) return;
    element.dispatchEvent(new Event(eventName, { bubbles: true }));
}

export function captureClickableFilterFocus() {
    const activeEl = document.activeElement;
    if (!activeEl || !activeEl.classList.contains("clickable-filter")) return null;
    return {
        col: activeEl.getAttribute("data-col"),
        val: activeEl.getAttribute("data-val"),
        rowIdx: activeEl.getAttribute("data-row-idx")
    };
}

export function restoreClickableFilterFocus(container, focusInfo) {
    if (!container || !focusInfo) return;
    const filters = Array.from(container.querySelectorAll(".clickable-filter"));
    const match = filters.find(el =>
        el.getAttribute("data-col") === focusInfo.col &&
        el.getAttribute("data-val") === focusInfo.val &&
        el.getAttribute("data-row-idx") === focusInfo.rowIdx
    ) || filters.find(el =>
        el.getAttribute("data-col") === focusInfo.col &&
        el.getAttribute("data-val") === focusInfo.val
    ) || filters.find(el =>
        el.getAttribute("data-col") === focusInfo.col &&
        el.getAttribute("data-row-idx") === focusInfo.rowIdx
    );
    if (match) match.focus();
}

export function bindClickableFilters(container, handler) {
    if (!container) return;
    container.querySelectorAll(".clickable-filter").forEach(el => {
        const handleFilterAction = () => handler({
            col: el.getAttribute("data-col"),
            val: el.getAttribute("data-val"),
            el
        });

        el.addEventListener("click", handleFilterAction);
        el.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                handleFilterAction();
            }
        });
    });
}
