# Superset Security Debt Autopilot

An event-driven system that turns a security backlog into reviewed pull requests, using
[Devin](https://devin.ai) as the remediation engine rather than as an assistant.

Target repository: [`dq-hustlecoding/superset`](https://github.com/dq-hustlecoding/superset)
(a fork of [`apache/superset`](https://github.com/apache/superset)).

---

## The problem

Run any scanner against a mature codebase and you get a number nobody can act on. On the
Superset fork, a single pass produces:

| Scanner | Findings |
|---|---|
| OSV.dev (pinned PyPI dependencies) | **15 distinct CVEs** across 6 packages |
| Bandit (first-party Python) | **266 findings**, including 6 `HIGH` severity weak-hash sites |

The backlog is not a knowledge problem — every one of those findings comes with a
description and a suggested fix. It is a **throughput problem**. Each item needs someone to
open the file, work out whether the finding is real, decide what the right fix is for that
specific call site, make the change, and prove it did not break anything. That is 30 to 90
minutes of senior engineer time for a change that ships no customer value.

So it does not get done. What happens instead is visible in Superset's own source today:

```python
return hashlib.md5(source).hexdigest()[:12]  # noqa: S324
```

The finding is suppressed, the scanner goes quiet, and the risk stays. **This system exists
to close that gap.**

---

## Business case

The engineering framing above is real, but it is not why a VP funds this. The reason is that
**the remediation window is longer than the exploitation window**, and by a wide margin.

| | Reported industry figure |
|---|---|
| Average remediation time, applications | **~74 days** ([Edgescan 2025 Vulnerability Statistics Report](https://www.edgescan.com/the-vulnerability-backlog-crisis-why-45-of-enterprise-vulnerabilities-never-get-fixed/)) |
| Time to fix open-source vulnerabilities | **~110 days**, up from 49 days in 2018 ([Snyk, State of Open Source Security](https://go.snyk.io/state-of-open-source-security-report-2022.html)) |
| Average time from disclosure to exploitation | **~15 days** ([Edgescan](https://www.edgescan.com/the-vulnerability-backlog-crisis-why-45-of-enterprise-vulnerabilities-never-get-fixed/)) |
| Discovered vulnerabilities still unpatched after 12 months | **45.4%**, of which 17.4% high or critical ([Edgescan](https://www.edgescan.com/the-vulnerability-backlog-crisis-why-45-of-enterprise-vulnerabilities-never-get-fixed/)) |
| Regulatory ceiling for known-exploited CVEs | **14 days** (CISA BOD 22-01); 30-90 days under FedRAMP/NIST guidance ([Praetorian](https://www.praetorian.com/security-101/mean-time-to-remediate-mttr)) |

Remediating in ~74 days against a ~15-day exploit window is not a backlog problem, it is a
losing race that repeats every scan cycle. And for anyone selling into regulated buyers, an
aged critical CVE is not an engineering embarrassment: it is an audit finding, a failed
security questionnaire, and a stalled deal.

**Measured against that baseline, this run produced review-ready PRs in ~20 minutes median**
(37.5 min mean, worst case 104) rather than weeks, at **$4.91 per remediated finding** —
roughly **29x cheaper** than the modelled cost of an engineer doing the same work. Three consequences that matter commercially:

1. **The risk window closes inside the exploit window.** The engineering half of remediation
   stops being the constraint.
2. **Compliance evidence becomes a byproduct.** Every finding carries a comment recording what
   changed, how it was verified, and the residual risk for the reviewer. That is the artifact
   auditors ask for, generated automatically instead of reconstructed at quarter end.
3. **Engineer time shifts from doing to reviewing.** Same headcount; the security backlog stops
   competing with the roadmap.

**The honest caveat:** this moves the bottleneck to code review rather than removing it. That
is a better constraint to have, but it is the new one, and it is exactly what the shadow-mode
rollout in *Where this goes next* is designed to measure.

---

## What it does

```
                    ┌──────────────────────────────────────┐
   nightly cron ───►│  SCANNER  (GitHub Actions, in fork)  │
   push to deps ───►│  OSV.dev CVE scan + Bandit           │
   manual run   ───►│  → deduplicated GitHub issues        │
                    └──────────────────┬───────────────────┘
                                       │  issues labeled `devin-autofix`
                                       ▼
                    ┌──────────────────────────────────────┐
                    │  ORCHESTRATOR  (FastAPI, Docker)     │
                    │                                      │
                    │  1. webhook  (HMAC-verified)         │
                    │  2. claim    (idempotency gate)      │
                    │  3. TRIAGE   (dispatch or escalate)  │
                    │  4. dispatch → Devin API v3          │
                    │  5. poll     (durable state machine) │
                    │  6. report   → issue comment + PR    │
                    └──────────────────┬───────────────────┘
                                       ▼
                    ┌──────────────────────────────────────┐
                    │  OBSERVABILITY                       │
                    │  dashboard · /metrics · JSON logs    │
                    │  success rate · MTTR · ACU · backlog │
                    └──────────────────────────────────────┘
```

1. **A scan is an event.** The scanner runs nightly, on any change to `requirements/`, or on
   demand. It queries OSV.dev for every pinned dependency and runs Bandit over first-party
   code, then files one GitHub issue per remediation unit.
2. **An issue is a work order.** Every issue body carries a machine-readable
   `<!-- autopilot:{...} -->` block. Labeling it `devin-autofix` fires the webhook.
3. **Triage decides whether to spend money.** Not every finding should go to an agent.
4. **Devin does the engineering.** One session per issue, with a playbook-specific prompt and
   a structured output contract.
5. **The result closes the loop.** The PR is linked back to the issue, labels are updated, and
   every transition is recorded for the dashboard.

---

## Results from a real run

One scan, one pass of the control loop, against the live fork:

| | |
|---|---|
| Findings ingested | **18** |
| Remediated with a PR | **8** — every finding dispatched succeeded, including all 3 `HIGH` |
| Escalated to a human by triage | **3** — no session spent |
| Failed | **0** |
| Still queued behind the 8-session daily budget | 7 |
| Success rate over attempted remediations | **100%** |
| Observed Devin spend | **$39.28** across 9 sessions |
| **Cost per remediated finding** | **$4.91** (fully loaded, including $3.70 wasted on the duplicate dispatch) |
| Median time from finding to review-ready PR | **~20 minutes** (mean 37.5 min; two long tails at ~100 min) |

Cost is **measured, not modelled**: $39.28 of real spend read from Devin's billing page,
against 8 remediated findings. The only modelled figure is the human comparison
(`ENGINEER_HOURS_PER_FINDING x ENGINEER_HOURLY_COST_USD`, default 1.5 h @ $95 = $142.50),
and the dashboard labels it `modelled` next to the measured number. At those values the
autopilot is roughly **29x cheaper per finding** than doing the work by hand.

Note on how spend is collected: the v3 API returns `acus_consumed = 0.0` for every session and
exposes no billing endpoint, so per-session cost is exported from **Settings → Usage & Limits →
Usage history** into [`costs/session-costs.json`](costs/session-costs.json). Pasted-in but real
beats API-native but zero.

**Remediated**

| Issue | Playbook | Severity | Time | Pull request |
|---|---|---|---|---|
| [#1](https://github.com/dq-hustlecoding/superset/issues/1) B324 weak hash, 6 sites | `static_analysis_fix` | HIGH | 14.5 min | [#21](https://github.com/dq-hustlecoding/superset/pull/21) |
| [#2](https://github.com/dq-hustlecoding/superset/issues/2) jaraco-context CVE-2026-23949 | `dependency_bump` | HIGH | 4.5 min | [#20](https://github.com/dq-hustlecoding/superset/pull/20) |
| [#3](https://github.com/dq-hustlecoding/superset/issues/3) python-multipart CVE-2026-53539 | `dependency_bump` | HIGH | 16.8 min | [#22](https://github.com/dq-hustlecoding/superset/pull/22) |
| [#6](https://github.com/dq-hustlecoding/superset/issues/6) B310 unaudited urlopen, 3 sites | `static_analysis_fix` | MEDIUM | 23.3 min | [#25](https://github.com/dq-hustlecoding/superset/pull/25) |
| [#7](https://github.com/dq-hustlecoding/superset/issues/7) pip CVE-2025-8869 | `dependency_bump` | MODERATE | 22.7 min | [#24](https://github.com/dq-hustlecoding/superset/pull/24) |
| [#5](https://github.com/dq-hustlecoding/superset/issues/5) B704 markup XSS, 7 sites | `static_analysis_fix` | MEDIUM | 103.7 min | [#27](https://github.com/dq-hustlecoding/superset/pull/27) |
| [#8](https://github.com/dq-hustlecoding/superset/issues/8) pip CVE-2026-3219 | `dependency_bump` | MODERATE | 100.3 min | [#26](https://github.com/dq-hustlecoding/superset/pull/26) |
| [#18](https://github.com/dq-hustlecoding/superset/issues/18) pip CVE-2026-13346 | `dependency_bump` | — | 14.5 min | [#19](https://github.com/dq-hustlecoding/superset/pull/19) |

**Escalated instead of automated** — these are the decisions the system got right by *not*
acting:

| Issue | Why it was refused |
|---|---|
| [#13](https://github.com/dq-hustlecoding/superset/issues/13) paramiko CVE-2026-44405 | No patched version exists upstream. An agent cannot fix what has not been released. |
| [#12](https://github.com/dq-hustlecoding/superset/issues/12) flask 2.3.3 → 3.1.3 | Major upgrade of a runtime dependency — breaking-change decision with production blast radius. |
| [#4](https://github.com/dq-hustlecoding/superset/issues/4) setuptools 80.9.0 → 83.0.0 | Same: major bump of a runtime dependency. |

Worth reading the diffs rather than the table. Two that make the point:

- **[#21](https://github.com/dq-hustlecoding/superset/pull/21)** — Devin read all six MD5 call
  sites, concluded each was a fingerprint or cache key rather than a security boundary,
  **preserved the digest output** so nothing persisted is invalidated, removed the `# noqa: S324`
  suppressions, and justified every site individually in the PR body.
- **[#20](https://github.com/dq-hustlecoding/superset/pull/20)** — the vulnerable package was a
  *transitive* dependency pulled in via `keyring`, so a direct pin would not have worked. Devin
  added a security floor to `requirements/development.in`, regenerated the lock with the
  repository's own `./scripts/uv-pip-compile.sh`, ran it twice to confirm CI's drift check stays
  green, and verified with `uv pip check` plus the one test module that touches `keyring`.

---

## Verification: I checked Devin's work rather than trusting it

Every PR claims it fixed the finding. Claims are not evidence, so the scanner was re-run
independently against each PR branch:

| Finding | Before (`apache/superset` master) | After (Devin's branch) | Verified how |
|---|---|---|---|
| B324 weak hash | **6** | **0** | `bandit -t B324` on the 5 changed files at PR [#21](https://github.com/dq-hustlecoding/superset/pull/21) head |
| B310 unaudited urlopen | **3** | **0** | `bandit -t B310` at PR [#25](https://github.com/dq-hustlecoding/superset/pull/25) head |
| B704 markup XSS | **7** | **0** | `bandit -t B704` at PR [#27](https://github.com/dq-hustlecoding/superset/pull/27) head |

And specifically checked that the findings were *fixed*, not silenced: the `# noqa: S324`
suppressions that exist on master are gone in PR #21, and no `# nosec` or scanner-config
exclusion was introduced in any branch. Devin also added 9 new tests in PR #25 and extended
`test_core.py` in PR #27.

One caveat found by this check, rather than assumed away — see *What did not work* below:
PR #25 does keep `# noqa: S310` on the `Request(...)` construction lines, with an inline
justification. The actual vulnerability (an opener that would follow `file:`) is genuinely
removed and verified, but the prompt told Devin not to leave suppressions, and it left three.

---

## What did not work

Worth reading before the architecture section — these are the parts that failed, and what
changed as a result.

**1. The autopilot opened two competing PRs on one issue.**
Issue #7 received both PR #23 and PR #24, from two Devin sessions started 28 seconds apart.
Cause: `_drain_queue` read a row as `queued` and *then* dispatched it — a check-then-act race.
With two reconcilers running (a webhook worker and the background loop), both saw the same row
as available and both paid for a session. Diagnosed from the two branch names and the
`dispatched` events sharing an issue number. Fixed by making the `queued -> dispatching`
transition an atomic conditional `UPDATE ... WHERE status = 'queued'`, so SQLite serialises
the write and exactly one worker can ever claim a finding (`db.try_lock_for_dispatch`).
PR #23 was closed as superseded. **This is the single most useful bug the project produced:**
with agents, a concurrency bug does not just corrupt state, it spends money and creates
review load.

**2. The Dockerized scanner produced a different backlog than the documented one.**
Running the README's own instructions (`docker compose run --rm scanner`) reported **2**
static findings where the host run reported **3**. Cause: the Dockerfile pinned
`bandit==1.8.0`, which does not implement B704. The published results had been produced with
host bandit 1.9.4. Fixed by moving bandit into `requirements.txt` pinned at `1.9.4` and
pinning it in the GitHub Actions workflow too. Found only because the documented setup was
actually executed rather than assumed.

**3. Devin sessions never reach a terminal API status on their own.**
A session that has finished its work, opened a PR and written its structured output still
reports `status: running`, `status_detail: working` — it idles waiting for a human. Polling
for a terminal status alone would hold a concurrency slot indefinitely on delivered work.
Completion is therefore defined by the *contract*: terminal `outcome` in the structured
output plus something to review. The API status is still honoured independently, which is
what catches errors and expiry.

**4. The API reports no cost data at all.**
`acus_consumed` came back `0.0` for every session, and every billing/usage endpoint 404s. The
dashboard initially rendered a confident `0.0`, which is worse than useless — it looks like a
measurement. Real per-session cost does exist, but only in the web UI under Settings → Usage &
Limits. It is now exported into `costs/session-costs.json` and joined onto each remediation, so
the dashboard shows measured spend with its provenance documented rather than a fabricated zero.
The per-session ACU ceiling is still enforced on the way in regardless.

**5. One session ended `suspended`.** The duplicate session on issue #7 stopped without
finishing. It cost a slot but produced no output, which is exactly what the timeout valve and
the `failed`/`timed_out` states exist to surface rather than hide.

---

## Why an autonomous agent, and not a script

This is the part that matters, so here is the concrete case.

Bandit rule **B324** fires at 6 places in Superset. A naive automation has two options, and
both are wrong:

- **Rewrite every `md5()` to `sha256()`.** This breaks Superset. Several of those hashes are
  cache keys and stable fingerprints whose values are persisted; changing the algorithm
  silently invalidates stored state.
- **Add `usedforsecurity=False` everywhere.** This is a suppression with extra steps. If any
  site *is* a security boundary, you have just documented the vulnerability instead of fixing it.

The right fix is different at each site, and you can only tell which is which by reading the
call site and understanding intent:

| Location | What the hash is actually for | Correct remediation |
|---|---|---|
| `superset/utils/hashing.py` | user-selectable digest for cache keys | declare non-security intent |
| `superset/utils/public_interfaces.py` | fingerprint of a function signature | declare non-security intent |
| `superset/config.py` | fingerprint of a config file | declare non-security intent |
| `superset/migrations/versions/...` | generated filter option name | judgement call, migration is frozen |

No regex, codemod, or Dependabot-style rule can make that distinction. **Reading unfamiliar
code and forming a judgement about intent is the specific thing an autonomous agent adds** —
and it is why the prompt in `app/triage.py` explicitly forbids blanket transformations and
requires per-site justification in the PR body.

The same argument applies to dependency work: bumping a pin is trivial, but reading the
upstream changelog, finding the breaking change, searching the codebase for affected call
sites, and fixing them is not.

---

## Design decisions worth reviewing

**Idempotency is enforced twice.** GitHub redelivers webhooks, and the nightly scanner
re-reports findings that are still open. Neither may cost a second session. A `UNIQUE`
constraint on `dedupe_key` in SQLite is the local gate (`app/db.py`), and `idempotent: true`
on the Devin API call is the remote one (`app/devin.py`).

**Triage runs before dispatch, and can refuse.** `app/triage.py` escalates instead of
spending a session when:
- the advisory has **no patched upstream version** — an agent cannot fix what does not exist;
- remediation needs a **major version bump of a runtime dependency** — that is a
  breaking-change decision with production blast radius, and an engineer should own it.

Dev-only tooling gets the opposite treatment: a major bump of `pip` or `pytest` has a blast
radius of CI, so it is automated. Encoding that distinction is what keeps the system from
producing PRs nobody dares to merge. In the current run, **3 of 18 findings were escalated
without spending anything**.

**Spend is bounded by policy, not by backlog size.** A concurrency cap and a rolling 24-hour
session budget are both enforced before dispatch, and every session carries a hard
`max_acu_limit`. A scanner that suddenly reports 200 findings cannot run away with the
budget. Queued work is drained **worst-severity-first**, so the budget always buys down the
highest risk available.

**The orchestrator owns the state machine, because the API has no completion callback.**
Sessions are polled, and every transition is persisted before it is acted on. The poller is a
*reconciler*: kill the process at any point and restart it, and it picks up every in-flight
session. A timeout valve prevents a stuck session from holding a concurrency slot forever.

**Devin's result is a contract, not prose.** Sessions are created with a
`structured_output_schema`, so the orchestrator machine-reads `outcome`, `pr_url`,
`files_changed`, `verification`, `residual_risk`, and `confidence`. Without that, the
"automation" would end at a human reading chat logs. The PR URL is resolved from three
sources in order: Devin's session record, its structured output, then a GitHub lookup.

**Two triggers, on purpose.** The webhook is the fast path. `POST /api/backfill` sweeps
GitHub for labeled issues the system has not claimed, which covers dropped deliveries,
downtime, and environments with no public ingress.

---

## Observability

> *"If I were an engineering leader, how would I know this is working?"*

The dashboard at `http://localhost:8000` is deliberately outcome-shaped, not process-shaped.

**Is it working?** — findings remediated vs. ingested (with a backlog burndown bar), success
rate over attempted remediations, pull requests opened, and mean time from finding to
review-ready PR.

**What is it costing me?** — sessions in flight against the cap, ACUs consumed, engineer
hours saved (configurable cost model), and how much was escalated to a human.

Per-finding drilldown gives status, playbook, Devin session link, PR link, duration, and
Devin's own self-reported summary and residual risk. The control-loop log shows every
transition, including throttles and budget exhaustion.

Machine-readable surfaces:

| Endpoint | Purpose |
|---|---|
| `GET /` | HTML dashboard (auto-refresh) |
| `GET /metrics` | Prometheus exposition |
| `GET /api/metrics` | JSON summary |
| `GET /api/remediations` | per-finding detail |
| `GET /api/events` | control-loop event log |
| `GET /healthz` | liveness |

Application logs are structured JSON, so they drop straight into Datadog or Loki.

---

## Running it

### Prerequisites

- Docker
- A Devin API key and organization ID — app.devin.ai → Settings → Devin API
- A GitHub token with `repo` scope on your fork

### 1. Configure

```bash
cp .env.example .env
$EDITOR .env
```

| Variable | Meaning |
|---|---|
| `DEVIN_API_KEY` / `DEVIN_ORG_ID` | Devin API v3 credentials |
| `GITHUB_TOKEN` / `GITHUB_REPO` | target fork, e.g. `you/superset` |
| `GITHUB_WEBHOOK_SECRET` | shared secret for webhook signature verification |
| `MAX_CONCURRENT_SESSIONS` | how many Devin sessions may run at once |
| `MAX_ACU_PER_SESSION` | hard ACU ceiling per session |
| `DAILY_SESSION_BUDGET` | rolling 24h cap on sessions started |
| `DRY_RUN` | rehearse the pipeline without creating sessions |

### 2. Start the orchestrator

```bash
docker compose up --build -d
open http://localhost:8000
```

### 3. Produce events (file the findings)

Against a local checkout of the fork:

```bash
git clone --depth 1 https://github.com/<you>/superset.git superset-src

# preview without writing anything
docker compose run --rm scanner --dry-run

# file the issues
docker compose run --rm scanner --github-repo <you>/superset
```

In production this step is the GitHub Actions workflow in
[`fork-workflow/security-scan.yml`](fork-workflow/security-scan.yml), installed into the fork
at `.github/workflows/security-scan.yml`. It runs nightly, on changes to `requirements/`, and
on manual dispatch.

### 4. Let the autopilot run

Point a GitHub webhook (`Issues` events, content type `application/json`, your
`GITHUB_WEBHOOK_SECRET`) at `https://<host>/webhooks/github`. For local development, tunnel it:

```bash
ngrok http 8000
```

If you have no public ingress, use the sweep instead — same code path:

```bash
curl -X POST http://localhost:8000/api/backfill
```

### Headless mode (no web layer)

```bash
python demo/run_cycle.py backfill    # claim, triage, dispatch in priority order
python demo/run_cycle.py watch       # run the reconciler until everything settles
python demo/run_cycle.py report      # metrics summary as JSON
```

---

## Repository layout

```
app/
  config.py          settings + policy knobs (works with or without pydantic)
  db.py              SQLite state store; idempotency gate; event log
  devin.py           Devin API v3 client + structured output contract
  github_client.py   issues, labels, comments, PR discovery, HMAC verification
  triage.py          dispatch-or-escalate policy + playbook prompt construction
  orchestrator.py    the control loop: claim → triage → dispatch → poll → report
  metrics.py         outcome-shaped read model + Prometheus exposition
  main.py            FastAPI: webhook ingress, control endpoints, dashboard
  templates/         dashboard
scanner/
  scan.py            OSV.dev + Bandit → deduplicated, machine-readable GitHub issues
fork-workflow/
  security-scan.yml  the scheduled trigger, installed into the Superset fork
demo/
  run_cycle.py       headless driver for the same control loop
```

---

## Where this goes next

- **More event sources, same pipeline.** Snyk/Trivy/CodeQL webhooks, Dependabot alerts, Jira
  ticket creation, or a failing CI job are all just another producer of a work order.
- **Feed review outcomes back into triage.** Every merged or rejected PR is a labeled example
  of whether that finding class was worth automating. Track per-rule merge rate and stop
  dispatching classes the team consistently rejects.
- **Devin playbooks and repo snapshots.** Moving the prompts into Devin playbooks and
  pre-warming a Superset environment snapshot cuts per-session setup cost significantly.
- **Route by ownership.** Use `CODEOWNERS` to assign each PR to the owning team, and
  `create_as_user_id` to attribute sessions so usage shows up per team.
- **Policy as the product.** The interesting knob for a VP is not "does it work" but "what is
  it allowed to do unattended" — severity thresholds, protected paths, and required human
  review for anything touching auth or migrations.
