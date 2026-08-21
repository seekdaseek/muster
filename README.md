# muster

Agent-access certification for Google Cloud. muster inventories the agents,
tools, identities and runtime workloads on a GCP project, then issues a
verdict per subject: **REVOKE**, **CERTIFY**, or **ABSTAIN** — each carrying
the evidence it was decided from.

Built for the All Things Agentic hackathon (Fortified Enterprise Fleet track),
August 2026.

## The design decision everything else follows from

**The language model has no code path to a verdict.**

Verdicts are decided in `src/verdict.py` — a pure module with no model, no
network and no clock — by deterministic rules over measured evidence. The
reviewer agent gathers evidence, calls the engine, and explains the result in
English. It cannot change one.

Any tool that lets a model decide "certified" can be talked into certifying.
This one can't, and that property is testable rather than asserted.

## The three verdicts

| Verdict | Requires |
| --- | --- |
| `REVOKE` | The evidence for a problem is **complete** and needs no usage data. |
| `CERTIFY` | Held permissions fully enumerated **and** usage evidence present **and** everything used is within what is held **and** nothing is `UNMEASURED`. |
| `ABSTAIN` | Anything else — with the missing evidence **named**. |

`CERTIFY` is deliberately hard to reach. On a project with no runtime traces
it is unreachable, and the report says so before listing anything:

```
CERTIFICATION CAMPAIGN   25 subject(s)
  REVOKE 3    CERTIFY 0    ABSTAIN 22

  CERTIFY WAS NOT REACHABLE IN THIS CAMPAIGN. No runtime traces
  exist on this project, so nothing could be shown to use only
  what it holds. Zero certifications is the engine working.
```

"We found nothing to certify" and "we could not have certified anything" are
different statements. `certify_reachable()` is the difference.

## What it measures

| Source | Read via |
| --- | --- |
| Registered agents, bindings, endpoints, MCP servers, services | `gcloud agent-registry <group> list` |
| Project IAM policy and service accounts | `gcloud projects get-iam-policy`, `gcloud iam service-accounts list` |
| Runtime workloads | `gcloud run services list` |
| Self-declared agent identity | `GET <workload>/.well-known/agent-card.json` |
| Content guardrail templates | `GET modelarmor.googleapis.com/v1/.../locations/global/templates` |

## The invariant

**A failed read is never recorded as an absent resource.**

`_parse` returns `None` on failure and `[]` only on success-with-empty-output.
Every source carries its exit code and stderr in a manifest. The report prints
source health *first*, and when anything failed it states that no finding
below derives from a failed source.

Verified by running `collect` with no `gcloud` on `PATH`: it reports eight
failed sources, not an empty fleet.

The same distinction runs through everything. An agent card that is
**unreachable** is not a card that is **absent**. A usage record of `None`
(unmeasured) is not `[]` (measured and empty) — a principal proven to have
invoked nothing can be judged; one with no trace at all must abstain.

## Findings it makes

Rules are deterministic and never infer from naming conventions:

- **`primitive-role-on-non-human-identity`** — a service account holding
  `roles/owner`, `roles/editor` or `roles/viewer`. Evidence lists *every* role
  held, not only the one that triggered the rule.
- **`self-declared-agent-not-registered`** — a workload serving an A2A agent
  card that is absent from the registry. Self-declared, not guessed from a
  name.
- **`catalog-label-misidentifies-service`** — a registry entry whose
  `displayName` matches neither its URN's service segment nor its endpoint
  host. Compared deterministically; malformed input is `UNMEASURED`, never a
  false mismatch.
- Tools that omit `readOnlyHint`, reported in three distinct states —
  `declared` / `partial` (block present, hint absent) / `absent` (no block).
  Collapsing them would overclaim.
- Tool names offered by more than one MCP server, where an agent wired to both
  has an ambiguous call target.

## Address matching

The Cloud Run API reports one URL per service. A service can answer on more —
measured: `status.url` and `status.address.url` were identical while the
project-number form returned `200` and appeared nowhere in the resource.

So matching is a set intersection over `status.url`, `status.address.url`,
`traffic[].url`, and the derived `https://SERVICE-PROJECTNUMBER.REGION.run.app`
form — the last built only when the project number *and* the region label are
both known. No region label, no derivation. When derivation isn't possible the
report warns that the address set is incomplete, because widening a set does
not prove it complete.

## Spin-up

Tested on macOS with Python 3.12 and Google Cloud SDK 580.0.0.

**1. Clone and create the environment.** Python 3.10+ is required —
`google-adk` will not install on 3.9.

```
git clone https://github.com/seekdaseek/muster.git
cd muster
python3.12 -m venv .venv
.venv/bin/pip install google-adk google-cloud-aiplatform
```

**2. Install and authenticate the Google Cloud SDK.**

```
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

**3. Enable the APIs muster reads from.** Enabling is free; charges come from
use. `agentregistry` is a separate API and is easy to miss — it is not part
of `aiplatform`.

```
gcloud services enable \
  agentregistry.googleapis.com \
  aiplatform.googleapis.com \
  run.googleapis.com \
  modelarmor.googleapis.com \
  logging.googleapis.com \
  iam.googleapis.com \
  cloudresourcemanager.googleapis.com \
  --project YOUR_PROJECT_ID
```

**4. Provide a Gemini API key** — only the agents need it; the rule engine
and CLI do not. Put it in a `.env` beside the repo. The loader reports the
key's name and length, never its value.

```
printf 'Paste your Gemini API key: '
read -rs K; echo
printf 'GOOGLE_API_KEY=%s\n' "$K" > ../.env
chmod 600 ../.env
unset K
```

**5. Run the tests.** They are offline — no network, no cloud, no key. Under
an interpreter without `google-adk` the agent tests skip rather than error.

```
python3 -m unittest discover -s tests
```

**6. Run it.**

```
python3 bin/muster.py run --project YOUR_PROJECT_ID          # engine only
.venv/bin/python agent/reviewer_fleet.py --project YOUR_ID   # the agent fleet
.venv/bin/python agent/reviewer_agent.py --project YOUR_ID   # single reviewer
```

**Optional — deploy a workload for the shadow detection to find.** This is
the subject under review, not part of muster.

```
gcloud services enable cloudbuild.googleapis.com --project YOUR_PROJECT_ID
cd shadow && gcloud run deploy invoice-triage --source . \
  --region us-central1 --allow-unauthenticated \
  --min-instances 0 --max-instances 1
```

### Permissions

muster reads only. Beyond standard viewer roles it needs
`roles/agentregistry.viewer`. A Cloud Build deploy of the sample workload
additionally needs `roles/cloudbuild.builds.builder` on the build service
account.

### Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the system diagram, the
separation-of-concerns table, and how a worker agent that loops, invents or
dies is handled.

## The reviewer fleet

Three specialised agents on Gemini 3.5 Flash via Google ADK, coordinated by
code rather than by a model:

| Agent | Owns | Cannot |
| --- | --- | --- |
| Surveyor | inventory the fleet | gather evidence, write the record |
| Investigator | close evidence gaps that have a route | inventory, write the record |
| Recorder | write the auditor-facing record | inventory, gather evidence |

Tool sets are disjoint and asserted so. A worker that loops is refused by the
loop guard; one that invents an identifier or a count has it caught by a
check against the measured evidence and kept out of the record; one that dies
degrades the campaign to the deterministic engine result with its verdicts
untouched.

## Layout

```
src/inventory.py   pure functions over measured JSON, no I/O
src/verdict.py     deterministic verdict rules, no model
src/fleet.py       role isolation, loop guard, claim verification, routing
src/reviewer.py    the gap-closing loop
src/closers.py     read-only evidence closers
src/collect.py     gcloud reads, manifest, agent-card probes
src/envload.py     .env loading that never exposes a value
src/report.py      rendering
bin/muster.py      CLI
agent/             the ADK agents
fixtures/          real JSON shapes captured from a live project
shadow/            a service that advertises itself as an agent and is not
                   registered, for exercising shadow detection against a real
                   workload rather than a fixture
tests/             212 tests, offline, no network
```

```
python3 -m unittest discover -s tests
```

## Known gaps

- No usage evidence source is wired yet, so `CERTIFY` is currently unreachable
  in practice. Cloud Trace is the intended source.
- The registry `bindings` list was empty on the project this was built
  against, so agent-to-tool entitlements are reported as unmeasured rather
  than enumerated.
