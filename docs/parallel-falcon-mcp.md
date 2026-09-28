# Running the harness in parallel with an existing Falcon MCP server

This repository ships the Falcon MCP harness from
[kyle9021/fal_con_2026_AI-Powered-Cloud-Security-Ops-Falcon-Mcp](https://github.com/kyle9021/fal_con_2026_AI-Powered-Cloud-Security-Ops-Falcon-Mcp)
(MIT, see `third_party/falcon-mcp-harness/LICENSE`; the upstream README is kept as
`docs/harness-README.md`). This page covers the one thing upstream does not:
running it **alongside a Falcon MCP server you already use**.

## What "in parallel" means here

```text
                ┌── falcon-mcp        (harness, this repo's .mcp.json)
Claude Code ────┤     read-only API client, 6 modules, guarded, audited
                │
                └── falcon-<name>     (your existing server, user/local scope)
                      its own API client, its own modules, ALSO guarded
```

Two independent `falcon-mcp` processes. Each has its own credentials, its own
module list and its own read-only setting. Claude sees both tool sets, named
`mcp__falcon-mcp__*` and `mcp__falcon-<name>__*`.

The harness's subagents (`falcon-query`, `falcon-asset-resolver`) list only
`mcp__falcon-mcp__*` tools, so fan-out work always goes to the harness server.
Your existing server is for the main conversation.

## The rule that matters: name it `falcon-*`

The upstream guardrail matched only `mcp__falcon-mcp__`. A second server with any
other name was **not governed at all**. Its write tools, including containment
and RTR, would run with no hook in front of them.

This repo changes both hooks and the `.claude/settings.json` matchers to govern
**every server whose name starts with `falcon` or `crowdstrike`**:

| Server name | Governed? |
|---|---|
| `falcon-mcp`, `falcon`, `falcon-prod`, `falcon_full`, `crowdstrike-falcon` | yes |
| `cs`, `edr`, `my-falcon-notes` | **no**. Rename it |

`./scripts/test-guardrail.sh` covers this ("Parallel Falcon servers").

If your existing server is also named `falcon-mcp`, only one of the two runs.
Claude Code resolves a name clash as local > project > user, so in this directory
one server silently shadows the other. Rename yours.

## Setup

### 1. Bring up the harness server on its own

```bash
cp env.example .env && chmod 600 .env   # a NEW read-only API client, see docs/api-scopes.md
./scripts/doctor.sh
./scripts/test-guardrail.sh
```

Give the harness **its own API client** (for example `claude-mcp-readonly`)
rather than reusing your existing server's credentials. That keeps layer 4, the
API scopes, read-only no matter what the other server can do. It also means
Falcon's API audit log tells you which of the two made a call.

### 2. Look at what you already have

```bash
claude mcp list
```

Note the name and scope of your existing Falcon server. If it lives in Claude
Desktop's config rather than Claude Code's, it is a separate app. It does not load
in this directory and there is nothing to reconcile. Stop here.

### 3. Rename or re-add the existing server under a `falcon-*` name

Point it at its **own** env file, outside this repo, so the two credential sets
never mix:

```bash
# remove the old entry (use the scope `claude mcp list` showed)
claude mcp remove <old-name> -s user

# re-add it under a governed name
claude mcp add falcon-full -s user -- \
  uvx --env-file ~/.config/falcon/full.env falcon-mcp==0.17.0
```

Pin the same `falcon-mcp` version as `.mcp.json` (`0.17.0`). The guardrail's
verb lists and `test-agents.py` are checked against that build.

`~/.config/falcon/full.env` can keep broader settings, for example more modules or
`FALCON_MCP_READ_ONLY=false`. **Inside this project the hook still denies its
writes** unless you set `HARNESS_ALLOW_WRITES=true`. Destructive tools
(contain, quarantine, delete, RTR execute) stay blocked whatever you set.

### 4. Start Claude Code here and confirm both servers

```text
/mcp
```

You should see `falcon-mcp` and `falcon-full` both connected. Then:

> Using falcon-mcp, how many hosts have not reported in 14 days?
> Using falcon-full, list enabled modules.

Tool calls for either server appear in `.cache/tool-audit.jsonl` with the full
tool name, so you can tell the servers apart.

## Choosing which server answers

| Use | Server |
|---|---|
| Playbooks (`/trace-vm-image`, `/image-sprawl`, `/posture-brief`), subagent fan-out, anything you'll `/crystallize` | `falcon-mcp` |
| Modules the harness leaves out (`ngsiem`, `idp`, `rtr` read, `customioa`...) | your server |
| Anything that writes | the Falcon console, or your server with `HARNESS_ALLOW_WRITES=true` set on purpose |

Say which server you mean in the prompt ("using falcon-mcp ..."). With two
servers, the model otherwise picks whichever tool description fits best, and the
evidence table should come from a single, known credential.

Tools from your server are **not** in the harness's `permissions.allow` list,
so Claude Code asks before each call. That is deliberate. Add specific read tools
to `.claude/settings.local.json` (gitignored) once you trust them. Don't add
them to the committed `settings.json`.

## Things to watch

- **Context cost doubles.** Two servers put two tool catalogues into context.
  Keep your server's `FALCON_MCP_MODULES` narrow too. See
  `docs/context-discipline.md`.
- **Same tenant, same rate budget.** Parallel servers and parallel subagents
  all add to that tenant's API traffic. A `429` is an `error`, never a zero (see
  `docs/parallelism.md`).
- **Different tenants.** If your existing server targets another CID (MSSP /
  `FALCON_MEMBER_CID`), label it in its name (`falcon-childco`), and don't mix
  results from both in one finding.
- **`.env` is only the harness's.** `settings.json` denies `Read(./.env*)`. Keep
  your other server's env file outside the repo, as in step 3.

## Using it with the SPL hunts in this repo

The README's hunts are Splunk SPL over Falcon event data (`ProcessRollup2`,
`DnsRequest`, `NetworkConnectIP4`, ...). Falcon MCP does not run SPL. The closest
equivalent is the `ngsiem` module, which runs CQL over the same event types. A
reasonable path:

1. Enable `ngsiem` on **your** server (not the harness's six-module set) and grant
   the NGSIEM read scope.
2. Ask Claude to translate one hunt from `README.md` into CQL and run it through
   that server. Check the results against a hunt whose answer you already know.
3. Once the translated hunt is stable, encode it with `/skill-template`, or
   `/crystallize` it so it runs without a model.
