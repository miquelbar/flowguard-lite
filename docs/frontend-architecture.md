# Frontend Architecture

FlowGuard Lite currently uses Vite with vanilla JavaScript modules and CSS. Do not introduce React, TypeScript, Tailwind, or another framework unless `missions/flowguard-lite/DECISIONS.md` records an explicit decision.

The frontend is organized around feature boundaries:

```text
web/src/
├── app/
├── features/
├── routes/
├── components/
│   └── ui/
├── lib/
├── loaders/
├── services/
└── styles/
```

## Responsibilities

`app/` owns application bootstrap, global state, route metadata, and shell lifecycle behavior.

`routes/` owns route parsing and serialization.

`features/` owns domain-specific UI modules. Each feature keeps its own rendering and event binding close together until there is enough code to justify subfolders such as `components`, `api`, or `model`.

`components/ui/` owns reusable, domain-agnostic UI primitives. Domain-specific components should stay inside their feature.

`lib/` owns shared infrastructure such as the API client, formatting, time-range helpers, sortable-table behavior, and safe device-link rendering. It must not become a generic dumping ground.

`loaders/` owns view data loading and state assignment.

`services/` owns cross-cutting browser/application behavior such as auth overlay state, global range controls, and status indicators.

`styles/` owns CSS by responsibility. `index.css` imports focused files for base tokens/reset, shell/sidebar/header, layout primitives, view-specific layout, charts, overlays, component groups, responsive rules, and theme overrides.

Current style responsibilities:

- `base.css`: tokens, reset, body constraints, scrollbar defaults.
- `shell.css`: app shell, sidebar, workspace header, global time controls, status indicator.
- `layout.css`: view containers, panels, split-panel primitives, panel body/header primitives.
- `views.css`: Overview, Settings, and view-specific layout rules.
- `charts.css`: traffic/chart frames, chart legends, chart tooltip/crosshair/empty states, network signal cards.
- `overlays.css`: auth and first-run wizard overlays.
- `buttons.css`, `cards.css`, `details.css`, `forms.css`, `tables.css`, `feedback.css`: reusable component-level rules.
- `theme.css`, `dark-core.css`, `analyst-theme.css`, `profile.css`, `dark.css`: neutral/dark/profile theme overrides.
- `responsive.css`: viewport-specific shell, split-pane, overlay, table, and form behavior.

## Route And State Contracts

Route parsing and serialization live under `web/src/routes/`. View modules should not invent alternate hash formats or parse route fragments ad hoc. Current deep-linkable state includes:

- device detail routes such as `#/devices/192.168.30.210`;
- device subnet filters such as `#/devices/subnet/192.168.30.0%2F24`;
- alert detail routes such as `#/alerts/<id>`;
- settings subsection routes such as `#/settings/network`.

Global application state lives in `web/src/app/state.js`. Mutations that affect routing, selected entities, dirty forms, or global range should use explicit state helpers from that module. Dirty-form protection is part of the route contract for Settings, Policies, and Notifications; route changes, refreshes, and selection changes must not silently discard edits.

Overview and Traffic are the only views currently allowed to use the global time range and auto-refresh. Auto-refresh must default to Off.

## Reusable UI Contracts

Shared UI primitives belong under `web/src/components/` only when there is real reuse. Current shared contracts include:

- `components/layout/splitPane.js` for master/detail close behavior and focus restoration.
- `components/ui/states.js` for table/panel empty, error, and loading states.
- `components/ui/focus.js` for visible focus movement and restoration.
- `components/ui/chart.js` for selected-range chart domains, time ticks, X/Y scales, empty SVG states, and HTML tooltips.

Devices, Alerts, Policies, and Notifications should continue to use the split-pane master/detail pattern. Do not add one-off tables, toolbars, close buttons, overlays, or empty states when these primitives already fit.

## Chart Semantics

Overview Attack Timeline, Traffic charts, and Device traffic chart use the selected global time range as their X-axis domain. They must not shrink the axis to the min/max timestamps returned by sparse data points. Charts expose `data-x-domain="selected-range"` plus `data-domain-start` and `data-domain-end` attributes so Cypress can verify axis semantics without pixel assertions.

Tooltips are HTML-based through the shared `#chart-tooltip` element and `components/ui/chart.js` helpers. Do not reintroduce native SVG `<title>` tooltips for primary charts. Tooltip labels and values must be escaped before insertion.

Empty chart states should use shared chart empty-state helpers or classes, and should explain that no data exists in the selected range rather than implying the feature is broken.

## Quality Gates

Frontend refactors are not complete until these commands pass:

```bash
make docker-ui-test
make docker-ui-smoke
```

`make docker-ui-test` runs Vite build and ESLint in Dockerized Node. `make docker-ui-smoke` runs Cypress against a Dockerized Vite server with mocked bounded API responses.

For the full pre-release gate, run:

```bash
make pre-release-gate
```

That gate runs product Go tests, the frontend gate, whitespace checks, and local mission-file ignore checks.

Host-native convenience targets exist for local development when Node is installed:

```bash
make ui-dev
make ui-check
make ui-cypress-open
```

The Docker targets remain authoritative on machines without host Node.

## Rules

- Prefer feature-first organization over broad global `views`, `utils`, `helpers`, `common`, or `misc` folders.
- Do not create empty architecture folders.
- Do not move code into shared abstractions until at least two real consumers exist.
- Keep visual components free of HTTP calls.
- Keep derived values calculated from state instead of storing duplicated state.
- Preserve loading, error, empty, and success states when refactoring.
- Preserve keyboard navigation, labels, visible focus, and mobile no-horizontal-overflow behavior.
- Preserve selected-range chart domains, shared HTML chart tooltips, and chart empty/error states.
- Keep `web/index.html` free of inline layout styles. Add reusable classes to `styles/` instead.
- Keep necessary horizontal overflow local to nav, range selector, settings nav, and table containers; do not allow document/body horizontal overflow.
- Treat view files above 300 lines as review candidates and files above 500 lines as strong split candidates.
- Split by responsibility, not by line count alone.

## Current known review candidates

No current frontend JavaScript module exceeds the 500-line strong split signal after the M29.1 feature split. These modules remain above 400 lines and should be reviewed in later M29 slices before adding behavior:

- `web/src/features/notifications/notificationsView.js`
- `web/src/features/policies/policiesView.js`

They should be decomposed only with characterization coverage and without changing routes, visual design, backend contracts, or polling behavior.
