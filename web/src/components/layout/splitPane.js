import { focusFirstVisible } from '../ui/focus.js';

export function bindSplitPaneClose(closeBtnIds, redirectHash, callback, focusSelectors = []) {
    closeBtnIds.forEach(id => {
        const btn = document.getElementById(id);
        if (btn) {
            btn.addEventListener("click", () => {
                if (callback) callback();
                window.location.hash = redirectHash;
                if (focusSelectors.length > 0) focusFirstVisible(focusSelectors);
            });
        }
    });
}
