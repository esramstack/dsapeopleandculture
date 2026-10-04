# Global acceptance criteria

Standing, project-wide acceptance criteria. One bullet per criterion. Spec
completion review judges each against the whole spec's implementation
(met / violated / not-applicable) and records the verdicts in the review
receipt. Absence of criteria, or of this file, changes nothing.

## Grammar

Each active criterion is a single markdown bullet:

```
- **G<N>:** <criterion prose>
```

Each bullet starts at the beginning of a line - indented or nested bullets are
ignored by the parser. Ids must be unique; gaps are allowed (deleting G2 leaves
G1, G3). Optional
scope hints live in the prose itself (e.g. `(scope: src/api/**)`). G-ids are
stable identity - do not renumber (same rule as spec R-IDs).

## Examples (commented out)

Uncomment or replace with your own. Commented lines are ignored by the parser.

<!-- - **G1:** Every route change regenerates the API contract. -->
<!-- - **G2:** No new dependency without a health check (scope: package.json). -->
<!-- - **G3:** User-facing strings live in the i18n catalog (scope: src/ui/**). -->

## Project criteria

- **G1:** Staff sessions never receive private HR data (phone, email, notes, former staff, hidden items, private files or letters); the server filters it, not the page. (scope: server/handler.js)
- **G2:** Every admin-only action is refused by the server for a staff token; hiding a button is never the protection.
- **G3:** User-controlled text reaches the page only through `esc()` / `textContent`; no inline `on*=` handlers. (scope: index.html)
- **G4:** After any edit to index.html, the CSP hash in vercel.json matches (`python3 qa/csp.py` passes).
- **G5:** The security tests in qa/security pass (`node --test server.test.mjs` and `node browser.test.mjs`).
- **G6:** No secrets, passwords or keys appear in source, docs or commits; existing password hashes stay readable (no lock-outs).
