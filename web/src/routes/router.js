import {
    state,
    setSelectedDeviceIP,
    setSelectedDeviceSubnet,
    setSelectedAnomalyId,
    hasUnsavedChanges,
    clearAllDirtyFlags
} from '../app/state.js';

export class Router {
    constructor(routes, defaultView) {
        this.routes = routes;
        this.defaultView = defaultView;
        this.currentHash = null;
        this.ignoreNextHashChange = false;
    }

    init() {
        window.addEventListener("hashchange", () => this.handleRoute());
        this.handleRoute();
    }

    handleRoute() {
        if (this.ignoreNextHashChange) {
            this.ignoreNextHashChange = false;
            return;
        }

        const hash = window.location.hash || "#/";

        let matchedView = this.defaultView;
        let routeParam = null;

        const parts = hash.split("/");
        if (parts.length >= 2) {
            const prefix = parts[0] + "/" + parts[1];
            if (this.routes[prefix]) {
                matchedView = this.routes[prefix];
                if (parts.length >= 3) {
                    routeParam = parts.slice(2).join("/");
                }
            } else if (this.routes[hash]) {
                matchedView = this.routes[hash];
            }
        }

        if (this.currentHash && matchedView !== state.activeView && hasUnsavedChanges()) {
            if (!confirm("You have unsaved changes. Are you sure you want to discard them?")) {
                this.ignoreNextHashChange = true;
                window.location.hash = this.currentHash;
                return;
            } else {
                clearAllDirtyFlags();
            }
        }

        this.currentHash = hash;
        this.switchView(matchedView, routeParam);
    }

    switchView(viewName, param = null) {
        const views = ["overview", "dashboard", "devices", "anomalies", "policies", "notifications", "audit", "settings"];
        views.forEach(v => {
            const el = document.getElementById(`view-${v}`);
            if (el) {
                el.classList.toggle("active", v === viewName);
            }
            let navId = `nav-${v}`;
            if (v === "anomalies") navId = "nav-anomalies";
            const navLink = document.getElementById(navId);
            if (navLink) {
                const active = v === viewName;
                navLink.classList.toggle("active", active);
                if (active) {
                    navLink.setAttribute("aria-current", "page");
                } else {
                    navLink.removeAttribute("aria-current");
                }
            }
        });

        state.activeView = viewName;
        if (viewName === "devices") {
            if (param && param.startsWith("subnet/")) {
                setSelectedDeviceSubnet(decodeURIComponent(param.slice("subnet/".length)));
                setSelectedDeviceIP(null);
            } else {
                setSelectedDeviceSubnet("");
                setSelectedDeviceIP(param ? decodeURIComponent(param) : null);
            }
        } else if (viewName === "anomalies") {
            setSelectedAnomalyId(param);
        }

        // Trigger viewchange custom event so views can react
        window.dispatchEvent(new CustomEvent("viewchange", { detail: { viewName, param } }));
    }
}
