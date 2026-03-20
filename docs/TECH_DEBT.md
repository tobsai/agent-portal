# Tech Debt — Agent Portal

Observed during NEXT-059 architectural hardening pass. Items noted but not fixed.
Each item is tagged with severity: 🔴 High / 🟡 Medium / 🟢 Low.

---

## 🟡 No top-level `express.static('public/')` middleware

`server.js` serves CSS/HTML files via individual `res.sendFile` routes rather than
a top-level `express.static` mount. This means every new static asset (CSS, images,
scripts) requires an explicit route addition, and can silently 404 if forgotten.

**Recommendation:** Replace the per-file routes with:
```js
app.use(express.static(path.join(__dirname, 'public')));
```
Guard authenticated pages behind `requireAuth` middleware rather than relying on
static-serve to be absent. Current per-file approach is workable but fragile.

---

## 🟡 `scheduled_tasks` populated externally by raw DB inserts

The portal has no canonical POST endpoint for task registration from the agent — tasks
were inserted directly into the PostgreSQL DB. NEXT-059 added `POST /api/scheduled` with
ON CONFLICT / upsert semantics, but the external agent code still uses direct DB writes.
The agent should be updated to call `POST /api/scheduled` instead.

---

## 🟡 In-memory `agentThinkingStatus` not durable across clusters

The status freshness logic in `routes/work.js` compares `Date.now()` against the
in-memory `timestamp`. If the portal is horizontally scaled (multiple Railway replicas),
each instance has its own in-memory state. The DB fallback partially mitigates this but
the 30-second fresh window means cross-instance reads may return stale data.

**Recommendation:** Remove the in-memory layer and read DB on every GET (with a short
Redis/in-process cache if latency becomes an issue).

---

## 🟢 `public/style.css` CSS custom properties not shared with `work.css`

The `--color-*` and `--radius-*` tokens in `work.css (:root)` duplicate palette
definitions in `style.css`. They should be extracted to a shared `tokens.css`
imported by both, eliminating divergence risk.

---

## 🟢 Signals panel has no virtual-scroll / pagination

The signals list in `work.html` appends DOM nodes indefinitely. Long-running sessions
will accumulate unbounded DOM growth. A capped circular buffer (e.g. max 200 items)
would prevent memory creep in the browser.

---

*Last updated: NEXT-059 (2026-03-20)*
