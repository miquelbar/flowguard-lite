function isVisible(element) {
    if (!element) return false;
    const style = window.getComputedStyle(element);
    if (style.visibility === "hidden" || style.display === "none") return false;
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

export function focusElement(elementOrSelector) {
    const element = typeof elementOrSelector === "string"
        ? document.querySelector(elementOrSelector)
        : elementOrSelector;
    if (!isVisible(element) || typeof element.focus !== "function") return false;
    element.focus({ preventScroll: true });
    return true;
}

export function focusFirstVisible(selectors) {
    window.requestAnimationFrame(() => {
        for (const selector of selectors) {
            if (focusElement(selector)) return;
        }
    });
}

export function focusFirstVisibleOnMobile(selectors) {
    if (!window.matchMedia("(max-width: 1040px)").matches) return;
    focusFirstVisible(selectors);
}
