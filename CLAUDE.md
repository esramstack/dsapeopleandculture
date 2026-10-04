# DSA People & Culture portal

Single-page HR portal (`index.html`, served by Vercel from `main`) backed by the Supabase Edge Function `hr-portal` (`server/handler.js`, project `ioqvezimbrdaojbwsfbf`, "HR - DSA"). The server does all sign-in and decides what each role receives; staff must never receive private HR data. The GitHub repo is public.

## Rules for every change
- **CSP fingerprint:** `vercel.json` only lets the page's inline script run by its SHA-256 hash. After ANY edit to `index.html`, run `python3 qa/csp.py --fix`. A stale hash makes the live page dead.
- **Security tests:** run before shipping. `cd qa/security && npm install` (first time), then `node --test server.test.mjs && node browser.test.mjs`. They use throwaway QA data via `fake-supabase.mjs`; never test against the live project.
- **Server deploys:** `server/handler.js` changes go live only when the `hr-portal` function is redeployed (`--no-verify-jwt`; the function checks its own tokens). Keep the deployed copy identical to the repo.
- **Escape user data:** every value interpolated into HTML goes through `esc()`. No inline `on*=` handlers (the CSP blocks them).
- **Never commit secrets or passwords**, and never put the current passwords anywhere in source (including blocklists).
- The HR Agent (AI) feature is out of scope unless asked.

<!-- BEGIN FLOW-NEXT -->
<!-- flow-next:snippet:v3 -->
## Flow-Next

This project uses Flow-Next for ALL task tracking. `flowctl` comes from the flow-next plugin install — every flow-next skill resolves it itself, and on Claude Code it is also on PATH. Do NOT create markdown TODOs or use TodoWrite. Cold session: `flowctl brief` first — one bounded call (specs, ready tasks, memory); go deeper with `show`/`cat`/`anchor <task-id>`.

- Lifecycle: `flowctl brief` / `show fn-N.M` / `start fn-N.M` / `done fn-N.M --summary-file s.md --evidence-json e.json` (e.json: `{"commits": ["<sha>"], "tests": ["<cmd>"], "prs": []}`)
- BEFORE any other flowctl operation, or when unsure of a flag: run `flowctl usage` (CLI cheatsheet + orchestration recipes) or `flowctl --help`.
- BEFORE bridging work to another model/CLI (`codex exec`, `cursor-agent`, `claude -p`, `grok`) or picking an implementation/review model: run `flowctl usage` and follow "Orchestration & model steering" exactly.
- Creating a spec: write it directly — `flow-next:flow-next-plan` is task breakdown only. `flowctl spec create --title "Short title" --plan-file plan.md --json`, then `flow-next:flow-next-plan <spec-id>`. Scaffold cascade (first match wins): `SPEC.md` -> `spec.md` -> bundled template.
- Substantial replies (reports, reviews, multi-section answers): invoke `flow-next:flow-next-prose` BEFORE drafting — the artifact prose contract applies to chat replies too. Short conversational turns skip it.
- If `flowctl` is not found: your shell lacks the plugin's `scripts/` dir on PATH (only Claude Code injects it). Resolve it the way the skills do - the plugin install's `scripts/flowctl` (Claude/Droid: plugin-root env var; Codex: `${CODEX_HOME:-$HOME/.codex}/scripts/flowctl`; Cursor/Grok: two levels above any flow-next SKILL.md) - or update/reinstall the flow-next plugin. A repo with no `.flow/` yet: run `flow-next:flow-next-setup`.
<!-- END FLOW-NEXT -->

<!-- flow-next:model-routing:start -->
## Model routing

<!-- Scaffolded by /flow-next:setup as an EXAMPLE to edit. Every routing line
     below is commented out, so nothing is routed until you uncomment one.
     These are your preferences to fill in - never detected facts. flow-next
     does not know which models your account serves and never writes one here. -->

<!-- Grammar: <tier>: <model>   or   <tier>: <model> at <effort>
     Name the model ids YOUR harness and account actually serve - ask the
     harness for its list, then invoke one; ids change and vary per account. -->

<!-- reviewer: <model>                  - anything grading work someone else
     produced. Prefer a different family than the writer: a same-family review
     is not an independent verdict. Advice, not enforcement. -->
<!-- implementer: <model> at <effort>   - work handed to another harness (plan
     here, implement cheaper or faster there). Absent = the session model
     implements. -->
<!-- fast scout: <model>                - mechanical inventory scanning, where
     the cheapest tier is the correct one. -->
<!-- thinking scout: <model>            - analysis that degrades badly on a
     fast tier. -->

<!-- Unset is the default and the doctrine: planning, capture, interview,
     requirement analysis, every verdict, and the worker run on the session
     model. Effort strings pass through to the host untranslated. -->

<!-- Resolution at each dispatch site: an explicit instruction in the moment,
     then this block, then the agent definition's own default, then the session
     model. A model this harness cannot reach falls back to the session model
     with one note - routing never fails closed, and nothing here is validated. -->
<!-- flow-next:model-routing:end -->
