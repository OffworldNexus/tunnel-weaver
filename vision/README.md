# Tunnel Weaver — Console UX Vision (`vision/`)

A stand-alone, fully mocked SvelteKit reference application for the signed-in
Tunnel Weaver console. Nothing here talks to a relay: every organisation, user,
machine, service, time-series bucket, review item, and transient HTTP query
comes from `src/lib/mock/` and mutates in memory.

When implementing new console features in `frontend/`, use `vision/` as the
canonical reference for information architecture, user flows, component
selection, and Minitel visual craft.

## Run & check

```bash
cd vision
pnpm install       # first time only
pnpm run dev       # dev server
pnpm run check     # svelte-check (0 errors, 0 warnings)
pnpm run build     # static SPA build
```

Open `/sign-in` and choose a persona (`Ada Offworld` super admin, `Priya Nair`
org admin, or `Sam Okafor` user).

## Design & structure highlights

- **Strict role hierarchy (`super_admin → org_admin → user → machine`)**:
  - Admin accounts (`super_admin` and `org_admin`) own zero machines or tunnels
    of their own.
  - The left sidebar scopes to the current selection: `Fleet` only when no
    organisation is selected → `<Org Name>` sub-section with the native org
    admin menu when an organisation is selected → `<User Name>` sub-section when
    a user is selected.
- **Minitel hardware control primitives**:
  - **Action buttons (`src/lib/ui/Keycap.svelte`)**: 4-layer cut-corner physical
    keycaps (`pedestal`, `ring`, `cap`, `face`) across `primary`, `key`,
    `danger`, and `ghost` tiers (`md` and `sm`).
  - **Radio / mode selectors (`.chips` / `.chip` in `src/styles/global.scss`)**:
    recessed monospace videotex selector rail with square phosphor indicator
    pips and inverse-video active state.
  - **Boolean switches (`src/lib/console/Toggle.svelte`)**: panel-mounted SVG
    bat-handle toggle switch (`O | I`) with corner-riveted escutcheon plate,
    hexagonal bushing nut, and a tapered bat lever that swings from `-68°`
    (OFF) to `+68°` (ON).
- **Speed graphs (`AreaChart.svelte`, `BandwidthChart.svelte`, `DateRangePicker.svelte`)**:
  - Powered by `layerchart` + `d3-scale` + `d3-shape` in units per second
    (`B/s`, `KB/s`, `MB/s`, `req/s`) over 1-minute buckets, with `30d P50` and
    `30d P95` reference lines, a quantized stable y-domain ceiling, and a
    smooth slide-in animation when a new minute bucket arrives.
  - Unified time-window radio rail (`Live · 1h`, `Live · 3h` default,
    `Live · 24h`, and `@ark-ui/svelte` `DatePicker` custom date range).
- **Three-level Abuse Review & Ban Annotations (`/app/admin/review`, `/app/org/review`, `/app/org/review/[person]`)**:
  - Super-admin review board ranks organisations with unresolved abuse by
    response speed and moderation score (`Review org →` or `Ban org`).
  - Org review page lists offending users with visitor fingerprint counts and
    infraction tallies; clicking a user opens their Offense Page with visitor
    fingerprint telemetry, infraction breakdown bars, blurred/labelled image
    infraction samples, and sampled HTTP queries.
  - Clearing a user deletes suspicion records and recomputes user + org
    reputation; banning (`BanDialog.svelte`) records an admin annotation +
    non-content proof summary (`Why banned` block on the user/org page) and
    purges raw offending samples immediately.
- **Machine Detail, Transient Live Logs & Svaul Inspection Drawer (`MachineDetail.svelte`, `LogStream.svelte`, `Inspect.svelte`)**:
  - One-way `Kick machine` action (with confirmation modal) and type-to-confirm
    deletion (`ConfirmDeleteDialog.svelte` on `@ark-ui/svelte/dialog`).
  - Multi-select service scope (`ServiceMultiSelect.svelte`).
  - Transient live HTTP query capture (off by default, virtualized scroll list
    with smooth top-down row expansion) and `@harshmandan/svaul` right-hand
    inspection drawer featuring the Flux-Capacitor Y-junction byte diagram,
    aligned `168px` header columns, syntax-highlighted JSON/HTML/CSS/JS response
    bodies, large-payload download, and clipboard copy for response bodies and
    `cURL`.
