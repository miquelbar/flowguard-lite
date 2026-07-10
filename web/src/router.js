import { state } from './state.js';

export class Router {
    constructor(routes, defaultView) {
        this.routes = routes;
        this.defaultView = defaultView;
    }

    init() {
        window.addEventListener("hashchange", () => this.handleRoute());
        this.handleRoute();
    }

    handleRoute() {
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

        this.switchView(matchedView, routeParam);
    }

    switchView(viewName, param = null) {
        const views = ["overview", "dashboard", "devices", "anomalies", "policies", "notifications", "audit", "settings"];
        views.forEach(v => {
            const el = document.getElementById(`view-${v}`);
            if (el) {
                el.classList.toggle("active", v === viewName);
            }
            // Update active state of sidebar navigation links
            // (Note: anomalies link is named nav-anomalies but view is named view-anomalies)
            let navId = `nav-${v}`;
            if (v === "anomalies") navId = "nav-anomalies";
            const navLink = document.getElementById(navId);
            if (navLink) {
                navLink.classList.toggle("active", v === viewName);
            }
        });

        state.activeView = viewName;
        if (viewName === "devices") {
            if (param && param.startsWith("subnet/")) {
                state.selectedDeviceSubnet = decodeURIComponent(param.slice("subnet/".length));
                state.selectedDeviceIP = null;
            } else {
                state.selectedDeviceSubnet = "";
                state.selectedDeviceIP = param ? decodeURIComponent(param) : null;
            }
        } else if (viewName === "anomalies") {
            state.selectedAnomalyId = param;
        }

        // Trigger viewchange custom event so views can react
        window.dispatchEvent(new CustomEvent("viewchange", { detail: { viewName, param } }));
    }
}
