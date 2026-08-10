# Dashboard UX Overhaul — Implementation Plan

> **For Hermes:** Execute tasks sequentially. Each task builds on the previous.

**Goal:** Fix "Last Updated" time, curve filter dropdowns, add custom date/time picker with timezone, add loading states, fix stat trend percentages, add dynamic threat chart, improve review/escalate UX, and ensure new-user consistency.

**Architecture:** Pure frontend overhaul — no backend changes needed except a new `/api/articles/timeline` endpoint for chart data. Chart uses vanilla Canvas API (no library) to match zero-dependency ethos.

**Tech Stack:** Vanilla JS, CSS, HTML5 Canvas, Node.js/Express/SQLite backend

---

### Task 1: Fix "Last Updated" time display

**Objective:** Show "Never" or "No data yet" when no articles exist, instead of blank

**Files:** `public/js/app.js:288-299`

**Change:** In `fetchStats()`, after `relativeTime()`:
```
const relTime = relativeTime(stats.lastUpdated);
$('#last-updated-time').textContent = relTime || '--';
```

Also verify `relativeTime()` handles edge cases — it already has guards for null/NaN/future dates, but check the `diff < 0` case (returns "Just now" instead of blank).

**Verification:** Load dashboard with no articles → should show "--" not blank.

---

### Task 2: Curve filter dropdowns to match UI

**Objective:** Make select dropdowns more rounded and visually cohesive with the glassmorphism theme

**Files:** `public/css/styles.css:599-614`

**Changes:**
- `.filter-select`: `border-radius` from `var(--radius-sm)` (8px) → `10px`
- Add subtle backdrop-filter blur to match card style
- Add `background-color` with glass effect
- Add transition for hover state

---

### Task 3: Add "Custom" date/time option to time range filter

**Objective:** Add "Custom Range" as last option in time range dropdown, with date/time pickers and timezone selector

**Files:**
- `public/index.html:328-336` — add `<option value="custom">Custom Range...</option>`
- `public/css/styles.css` — styles for custom date picker modal/popover
- `public/js/app.js` — handle custom range selection, show date inputs, pass `start_date`/`end_date` to API

**Steps:**
1. Add `<option value="custom">Custom Range...</option>` to time-range select
2. On change to "custom", show a date-range popover below the select with:
   - Start date/time input
   - End date/time input  
   - Timezone selector (UTC, browser local, or pick from list)
   - Apply button
3. On Apply, construct ISO strings with timezone offset, set `state.filters.start_date` and `state.filters.end_date`, and fetch
4. Show selected range as a tag/chip near the filter bar

---

### Task 4: Add loading spinner on filter changes

**Objective:** Show a loader when filter changes trigger a data fetch

**Files:** `public/js/app.js`, `public/css/styles.css`

**Changes:**
- Add a `showLoader()` / `hideLoader()` function
- In `fetchArticles()`, show skeleton cards again (or a thin progress bar at top) when filters change
- Keep existing articles visible while loading (don't clear until new data arrives)
- Add a pulsing bar at top of feed during load

---

### Task 5: Fix stat trend percentages

**Objective:** Replace static "↑ 0%", "0 active", "0 live" with real calculated values

**Files:** 
- `public/js/app.js:288-299` — `fetchStats()`
- `src/database.js:725-765` — `getArticleStats()`

**Backend:** Add yesterday's threat count and previous-week critical/PoC counts so frontend can calculate deltas

**New fields in stats response:**
- `threatsYesterday` — for % change calculation
- `criticalVulnsPrev` — previous week's critical count
- `pocsDetectedPrev` — previous week's PoC count

**Frontend:** Calculate and display:
- Threats Today trend: arrow + percentage vs yesterday
- Critical Vulns: count + "this week" label  
- POCs Detected: count + "this week" label
- When values are 0, show "—" or "No data" instead of "0%"

---

### Task 6: Add dynamic threat chart between search bar and stats cards

**Objective:** A time-series chart showing threat volume, adjustable by time range

**Files:**
- `public/index.html` — add chart container between filter-bar and stats-bar
- `public/css/styles.css` — chart container styles
- `public/js/app.js` — Canvas-based chart rendering
- `src/routes/api.js` — new endpoint `/api/articles/timeline`
- `src/database.js` — `getArticleTimeline()` function

**Backend (`getArticleTimeline`):**
- Query articles grouped by day/hour (depending on range)
- Return `[{ date, count, critical, high, medium, low }]`
- Accept `days`, `userId`, `start_date`, `end_date` params

**Frontend chart:**
- Canvas-based line/bar chart
- X-axis: dates, Y-axis: count
- Stacked bars or lines colored by severity
- Tooltip on hover
- Time range selectors below chart (24h, 7d, 30d, custom)
- Chart range synced with filter time_range but independently adjustable

---

### Task 7: Improve review/escalate button UX

**Objective:** Make review state visible on article cards and improve button feedback

**Files:** `public/js/app.js:427-491`, `public/css/styles.css`

**Changes:**
- After clicking "Review" → button changes to "Reviewing..." with spinner, then to "In Review" (green)
- After clicking "Done" → shows checkmark, card gets subtle green border
- After clicking "Escalate" → button turns red, card gets red accent
- Show current user's review status prominently on the card
- Article action buttons should disable when already acted upon

---

### Task 8: Ensure new-user dashboard consistency

**Objective:** New users get the same polished dashboard with empty-state handling

**Files:** `public/js/app.js` — `initDashboard()`

**Changes:**
- Chart shows "No data yet — add sources to start tracking" when empty
- Stats cards show "—" instead of "0%" for trend values when no data
- Empty feed has clear CTA to add sources
- All null-safety checks throughout rendering

No backend changes needed — user isolation is already correct.

---

### Execution Order

1. Task 1 (Last Updated fix) — quick win, standalone
2. Task 2 (Dropdown curves) — CSS only
3. Task 5 (Stat trends) — backend + frontend, needed for Task 6 context
4. Task 6 (Chart) — biggest feature, depends on Task 5 backend
5. Task 3 (Custom date/time) — builds on chart time-range work
6. Task 4 (Loading states) — ties everything together
7. Task 7 (Review UX) — polish
8. Task 8 (New-user consistency) — final pass

---

### Risks
- Canvas chart: no external library means more code, but matches zero-dependency ethos
- Timezone handling: need to be careful with UTC vs local conversions
- Performance: chart data query for many articles could be slow — add index on `published_date`
