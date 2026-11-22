# TryBuildMe room pitches: Aidan Veselka

Streams: **AI Security** (pitch 1) and **Product Security** (pitches 2–3). All three come from what I
actually build: ITSM/help-desk workflows, access rules, integrations, and agentic AI tools.

> **Duplicate check (searched Nov 21, 2026).** TryHackMe already covers the *concepts* well. Its AI
> Security / Agentic AI path includes *LLM Pentesting*, *ASI01: Indirect Injection in Agentic Systems*,
> *ASI02: Tool Misuse & Exploitation*, *ASI03: Agent Identity & Privilege Abuse*, *Securing AI Systems*,
> *Agent Hardening*, and "Privilege Escalation via Agent Chain". On the web/API side there are *IDOR*,
> *Broken Access Control*, *API Pentesting*, and *Harder* (HMAC bypass). These pitches are meant to sit
> **next to** those rooms, not repeat them. Each is a hands-on chained exploit in one realistic
> enterprise app (an IT help desk), followed by a "fix it" task. I could only see public room
> descriptions and community writeups, so the TryHackMe team should confirm there's no overlap with
> unreleased or premium content.

---

## Pitch 1: DeskPilot: When the Help-Desk AI Becomes the Insider
**Stream:** AI Security · **Difficulty:** Medium · **Time for learner:** ~60 min
**Working prototype:** `sample-lab/` (Flask + deterministic rule-based agent, 3 flags, solver included)

**Scenario.** A company bolts an AI agent ("DeskPilot") and an auto-triage agent ("TriageBot") onto its
IT portal. The REST API enforces ownership correctly, but the AI layer quietly undoes it.

**Learning objectives**
- Tell the difference between an agent's *instructions* and real *authorization*, and show why
  "the system prompt says don't" is not access control.
- Exploit indirect prompt injection carried in a business record (a ticket description) against an agent
  that holds an over-privileged tool.
- Chain agent tool access into a confused-deputy allowlist bypass (prefix check vs. parsed hostname).
- Recommend concrete fixes: tool-level authz on the end user's identity, least-functionality tool sets,
  human approval for privilege changes, and parse-then-compare allowlists.

**Task outline**
1. Intro and scenario: the help desk, both agents, and the rules of engagement.
2. Recon: list the agent tools, read the KB, and note that the REST API returns 403 on others' tickets.
3. Prompt-only authorization: use a role claim to make the agent read another user's ticket → **Flag 1**.
4. Indirect injection: a ticket with a `TRIAGE-NOTE` makes TriageBot run `grant_role` → `/admin` → **Flag 2**.
5. Confused deputy: abuse the status tool's prefix allowlist with userinfo syntax to reach the internal
   secrets service using the agent's token → **Flag 3**.
6. Read the trace: use the tool-call trace and audit log to reconstruct what happened (questions).
7. Fix it: pick the control that closes each bug, and explain why prompt hardening alone fails (questions).

**Flags:** `THM{r0le_cl41ms_4re_n0t_4uth0r1z4t10n}`, `THM{tr14ge_b0t_0b3y3d_th3_t1ck3t}`,
`THM{pr3f1x_4ll0wl1st_us3r1nf0_byp4ss}`. Values are set by env var, so they can be rotated per
deployment.

**How it differs from the closest rooms.** *LLM Pentesting* centres on fingerprinting, system-prompt
extraction, and jailbreaks against a single assistant. The *ASI01–03* rooms are mostly about
investigation and logs. DeskPilot is an **offensive chain across two cooperating agents and a
non-AI bug**, and it ends in real privilege escalation inside an ITSM app. It also uses a
**deterministic mock agent**: flags are 100% reproducible, it costs nothing to host, and no model API
is involved. That avoids the "the LLM didn't cooperate this time" problem.

**Estimated build time:** ~25–35 hours (the prototype is already done; the remaining work is room text,
hints, UI polish, testing on the TryHackMe VM image, and review fixes).

---

## Pitch 2: Ticket to Ride: Broken Access Control in an ITSM Platform
**Stream:** Product Security · **Difficulty:** Easy–Medium · **Time for learner:** ~60 min

**Scenario.** An internal ticketing/change-management app ("TryDesk") hides fields and buttons in the
UI. Some of the server endpoints forget to apply the same rules.

**Learning objectives**
- Distinguish UI-side rules (hidden fields, read-only forms) from server-side ACLs, and test them separately.
- Find access-control gaps in *secondary* endpoints: list views, CSV export, search/aggregate counts,
  and attachment downloads. The main record page often enforces the rule while these do not.
- Exploit workflow/state-machine flaws: self-approving your own change request, and skipping states.
- Abuse a misconfigured delegation/"act on behalf of" feature (vertical escalation).
- Write a minimal ACL test matrix (role × object × action) that would have caught every bug.

**Task outline**
1. Intro: how ITSM apps model roles, groups, records, and approvals.
2. "The form says read-only": change a read-only field (priority/assignment) by editing the request.
3. Field-level leak: the record page hides `caller_ssn_last4`/salary fields, but the CSV export and
   list API return them → **Flag 1**.
4. Aggregate oracle: a search "count" endpoint leaks whether hidden confidential tickets match a
   keyword. Extract a secret one character at a time with a small script → **Flag 2**.
5. Approval bypass: move your own change request from `Assess` to `Implement` by PATCHing `state`
   and `approved_by` → **Flag 3**.
6. Delegation abuse: the "delegate my approvals" feature lets you pick *any* user as the delegator,
   including a manager → **Flag 4**.
7. Defend: fill in the ACL matrix and choose the server-side fix for each bug.

**Flags:** 4 (`THM{...}` per task, rotatable).

**How it differs.** *IDOR* and *API Pentesting* teach object-level ID tampering (BOLA, mass assignment)
in a shop/user API. *Broken Access Control* (OWASP) uses a single admin-flag flip. This room skips the
"change the id" trick and focuses on **field-level, aggregate, and workflow/approval** access control:
the bugs that matter in enterprise platforms like ITSM, HR, and CRM tools.

**Estimated build time:** ~30–40 hours.

---

## Pitch 3: Integration Hub: Abusing a Misconfigured Internal API
**Stream:** Product Security · **Difficulty:** Medium · **Time for learner:** ~75 min

**Scenario.** A help-desk platform accepts inbound webhooks from monitoring tools and runs a
"scripted" internal REST API for integrations. The integration account was set up in a hurry.

**Learning objectives**
- Enumerate an internal API from leaked OpenAPI/Swagger docs and client-side config.
- Recognise over-scoped integration credentials (a wildcard-scoped key meant for one endpoint).
- Break webhook authenticity: a signature check that only runs when the header is present, plus
  timestamp/replay weaknesses.
- Exploit a "debug"/legacy API version that skips the auth middleware.
- Apply fixes: scoped short-lived tokens, mandatory constant-time HMAC with freshness windows, and
  retiring legacy routes.

**Task outline**
1. Intro: how ITSM integrations work (inbound webhooks, outbound REST, integration users).
2. Recon: find `/api/docs` and an integration key embedded in a front-end bundle → **Flag 1**.
3. Scope abuse: the key meant for `POST /incidents` also works on `/users` and `/config` → **Flag 2**.
4. Webhook forgery: drop the signature header and the event is still accepted. Use it to create a
   P1 incident that auto-pages and auto-runs a "remediation" job → **Flag 3**.
5. Replay: a captured signed event can be replayed because there is no timestamp/nonce check (questions).
6. Legacy route: `/api/v0/` skips the auth middleware entirely → **Flag 4**.
7. Defend: match each bug to its fix, and pick the logging signal that would have caught it.

**How it differs.** *API Pentesting* covers BOLA, broken auth, and mass assignment in a customer API.
*Harder* includes a PHP-specific HMAC type-juggling trick inside a broader box. This room is about the
**machine-to-machine integration surface** (integration accounts, token scopes, webhook signing and
replay, legacy versions), which is the part of enterprise apps most often configured by admins rather
than developers.

**Estimated build time:** ~30–40 hours.
