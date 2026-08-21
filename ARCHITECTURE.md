# muster — architecture

## The whole system

```
                        ┌──────────────────────────────────┐
                        │   COORDINATOR  (code, not a model)│
                        │   src/fleet.py  route()           │
                        │   • routes by dependency          │
                        │   • owns the loop guard           │
                        │   • verifies every claim          │
                        └───┬──────────┬──────────┬─────────┘
                            │          │          │
        ┌───────────────────▼──┐  ┌────▼────────┐ │ ┌──────────────────┐
        │  SURVEYOR            │  │ INVESTIGATOR│ └►│  RECORDER        │
        │  Gemini 3.5 Flash    │  │ Gemini 3.5  │   │  Gemini 3.5      │
        │  via Google ADK      │  │ Flash / ADK │   │  Flash / ADK     │
        │                      │  │             │   │                  │
        │  tool: survey_fleet  │  │ tool:       │   │ tool:            │
        │                      │  │ investigate_│   │ read_campaign    │
        │                      │  │ gaps        │   │                  │
        └──────────┬───────────┘  └──────┬──────┘   └────────┬─────────┘
                   │                     │                   │
                   │  tool sets are disjoint — no agent can reach another's
                   │                     │                   │
        ┌──────────▼─────────────────────▼───────────────────▼─────────┐
        │              RULE ENGINE   src/verdict.py                     │
        │              pure · deterministic · no model, no network      │
        │                                                               │
        │        REVOKE ◄── evidence complete, no usage data needed      │
        │        CERTIFY ◄── held enumerated + usage present +           │
        │                    used ⊆ held + nothing UNMEASURED            │
        │        ABSTAIN ◄── anything else, missing evidence NAMED       │
        └──────────────────────────┬────────────────────────────────────┘
                                   │  reads only
        ┌──────────────────────────▼────────────────────────────────────┐
        │           EVIDENCE LAYER   src/collect.py · src/inventory.py   │
        │           a failed read is never an absent resource            │
        └───┬────────┬────────┬────────┬────────┬────────┬───────────────┘
            │        │        │        │        │        │
     ┌──────▼──┐ ┌───▼────┐ ┌─▼──────┐ ┌▼─────┐ ┌▼──────┐ ┌▼────────────┐
     │ Agent   │ │ Cloud  │ │ Cloud  │ │ IAM  │ │ Model │ │ A2A agent   │
     │ Registry│ │ Run    │ │ Audit  │ │policy│ │ Armor │ │ card probe  │
     │ 5 groups│ │services│ │ Logs   │ │+SAs  │ │global │ │ well-known  │
     └─────────┘ └────────┘ └────────┘ └──────┘ └───────┘ └─────────────┘
                        G O O G L E   C L O U D
```

## Why the model sits outside the decision

Any tool that returns a verdict can be talked into returning the wrong one.
So no agent has one. The rule engine decides before a model is invoked and
again after, over the same measured evidence. The agents choose what to look
at and explain what was found; they cannot move an outcome.

This is enforced by tests, not by the prompt: no tool accepts an argument, no
tool name contains `certify`/`revoke`/`decide`/`override`, and the three tool
sets are asserted disjoint.

## Separation of concerns

| Agent | Owns | Cannot |
| --- | --- | --- |
| Surveyor | `survey_fleet` — inventory | gather evidence, write the record |
| Investigator | `investigate_gaps` — close gaps | inventory, write the record |
| Recorder | `read_campaign` — read verdicts | inventory, gather evidence |

The coordinator routes by dependency: nothing is investigated before the
fleet is known, nothing recorded before investigation has had its one pass.

## Failure tolerance

Three ways a worker goes wrong, three structural answers:

**It loops.** `LoopGuard` refuses a tool call already served with identical
arguments, and enforces a total call budget so an agent that varies its
arguments forever still runs out. Refusals are recorded, not hidden.

**It invents.** `verify_claims()` extracts every identifier (service account,
URN, URL, IAM role) and every number from the worker's prose and checks each
against an evidence index. Unsupported tokens are flagged, reported, and kept
out of the record.

The index holds the measured sources **and every tool return value**, folded
in as each call completes. That second half is not incidental: a tool that
computes a figure returns a number appearing nowhere in the records it was
derived from, so indexing only the sources flags an agent for correctly
repeating its own tool's output. This was found by the check firing on a
true statement during the first live fleet run.

It is a conservative check over tokens that must have come from evidence —
not a semantic truth test. It will not catch a false claim assembled
entirely from true tokens, and it does not pretend to.

**It dies.** The campaign degrades to the deterministic engine result with
`verdicts_unaffected: true`. No verdict has ever depended on a worker
succeeding.

## Evidence sources

| Source | Read via |
| --- | --- |
| Agents, bindings, endpoints, MCP servers, services | `gcloud agent-registry <group> list` |
| Project IAM policy, audit config, service accounts | `gcloud projects get-iam-policy`, `gcloud iam service-accounts list` |
| Runtime workloads | `gcloud run services list` |
| Usage evidence | `gcloud logging read` over Cloud Audit Logs |
| Self-declared agent identity | `GET <workload>/.well-known/agent-card.json` |
| Content guardrails | `GET modelarmor.googleapis.com/v1/.../locations/global/templates` |

Model Armor is reached on the **global** host directly: gcloud routes to a
regional `*.rep.googleapis.com` endpoint that returns 403 on this project
while the global host returns 200 with the same credentials.

## The invariant that runs through every layer

**A failed read is never recorded as an absent resource.** `_parse` returns
`None` on failure and `[]` only on success-with-empty-output. Every source
carries its exit code in a manifest. The report prints source health first
and, when anything failed, states that no finding below derives from it.

The same distinction repeats: an agent card that is *unreachable* is not one
that is *absent*; a usage record of `None` (unmeasured) is not `[]` (measured
and empty); a tool that ran and found nothing has answered, a tool that
errored has not.

## Google stack used

- **Gemini 3.5 Flash** via **Google ADK** (`google-adk`), three agents
- **Cloud Run** — hosts the workload under review
- **Agent Registry**, **Cloud Audit Logs**, **Cloud IAM**, **Model Armor**
- **Cloud Build** — builds the deployed service
