# DeskPilot

A deliberately vulnerable ITSM help-desk portal with a deterministic, rule-based mock AI agent. Built as a sample TryHackMe room for a [TryBuildMe](https://careers.tryhackme.com/jobs/8094939-trybuildme-become-a-room-builder) room-builder application.

**Training use only.** This lab contains intentional vulnerabilities. Bind it to `127.0.0.1` and do not expose it to a public network. There are no external APIs, no real secrets, and no outbound network calls.

Author: [Aidan Veselka](https://github.com/Poison675)

## What you will learn

The underlying REST API enforces ticket ownership correctly. The AI layer in front of it does not. The room chains three bugs:

1. **Prompt-only authorization** — the agent is told not to show other people's tickets, but the tool itself can read them. A role claim is enough to get Flag 1.
2. **Indirect prompt injection** — a `TRIAGE-NOTE` planted in a ticket description makes TriageBot run an over-privileged `grant_role` tool, escalating you to admin for Flag 2.
3. **Confused-deputy allowlist bypass** — the status tool checks that a URL *starts with* a safe prefix, then fetches the *parsed* hostname with the agent's internal token, which yields Flag 3.

A writeup with the intended path and the fix for each bug is in [WRITEUP.md](WRITEUP.md). Two further room pitches (Product Security) are in [PITCHES.md](PITCHES.md).

The "agents" are rule-based, so every flag is deterministic. No model API is involved.

## Requirements

- Python 3.11 or later
- Docker is optional (see below)

## Run without Docker

```bash
python3 -m venv .venv
.venv/bin/pip install -r app/requirements.txt
HOST=127.0.0.1 PORT=8080 .venv/bin/python app/app.py
```

In another terminal:

```bash
python3 solver.py http://127.0.0.1:8080
```

Then open http://127.0.0.1:8080. Log in as `student` / `student`.

`POST /api/reset` restores the initial state (the solver does this first).

## Run with Docker

If you use Docker, Compose publishes the port on loopback only:

```bash
docker compose up --build -d        # 127.0.0.1:8080 only
python3 solver.py http://127.0.0.1:8080
docker compose down
```

## Flags

Default values (override with `FLAG1`, `FLAG2`, and `FLAG3` in the environment if you want to rotate them):

- `THM{r0le_cl41ms_4re_n0t_4uth0r1z4t10n}`
- `THM{tr14ge_b0t_0b3y3d_th3_t1ck3t}`
- `THM{pr3f1x_4ll0wl1st_us3r1nf0_byp4ss}`

The admin account password is randomly generated at startup. You are not supposed to log in as admin; Flag 2 is the intended path to that role.

## Layout

- `app/app.py` — the lab
- `solver.py` — standard-library proof that all three flags are reachable
- `WRITEUP.md` — learner writeup and recommended fixes
- `PITCHES.md` — this room plus two further product-security pitches
- `Dockerfile` and `docker-compose.yml` — optional local container, bound to 127.0.0.1

## Disclaimer

Do not use this code in production or on a shared network. Session keys and internal tokens are generated at runtime and are not real credentials.
