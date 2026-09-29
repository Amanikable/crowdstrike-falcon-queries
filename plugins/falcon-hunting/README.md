# falcon-hunting: a Claude Code plugin

Hunt in CrowdStrike Falcon from Claude Code. The plugin bundles:

- **[falcon-mcp](https://github.com/CrowdStrike/falcon-mcp)**, CrowdStrike's MCP server
  for the Falcon platform, pinned to `0.19.0`. It starts in **read-only** mode with the
  `ngsiem`, `detections`, `hosts` and `intel` modules.
- **`falcon-threat-hunting` skill**: the hunts from this repository rewritten from
  Splunk SPL into NG-SIEM CQL, plus SPL-to-CQL translation rules and a
  run-and-verify workflow.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) installed, which provides `uvx`
- A Falcon API client with these scopes: `NGSIEM:read` and `NGSIEM:write`, plus
  `Alerts:read`, `Hosts:read` and the Intel read scopes for the pivot tools. See the
  [falcon-mcp module overview](https://developer.crowdstrike.com/falcon-mcp/modules/overview/).

## Install

```bash
# In your shell profile or before launching Claude Code
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
export FALCON_BASE_URL="https://api.us-2.crowdstrike.com"   # optional, default US-1
```

Then, inside Claude Code:

```
/plugin marketplace add amanikable/crowdstrike-falcon-queries
/plugin install falcon-hunting@crowdstrike-falcon-queries
```

To test a local checkout without installing: `claude --plugin-dir ./plugins/falcon-hunting`.

## Configuration

Change these by setting environment variables before you launch Claude Code:

| Variable | Default | Purpose |
| --- | --- | --- |
| `FALCON_CLIENT_ID` | (required) | API client ID |
| `FALCON_CLIENT_SECRET` | (required) | API client secret |
| `FALCON_BASE_URL` | `https://api.crowdstrike.com` | Region API URL |
| `FALCON_MCP_MODULES` | `ngsiem,detections,hosts,intel` | Modules to load |
| `FALCON_MCP_READ_ONLY` | `true` | Set to `false` to expose tools that change tenant state |

## Usage

Ask for a hunt in plain language, or call the skill directly:

```
/falcon-hunting:falcon-threat-hunting look for renamed executables in the last 3 days
Hunt for LOLBins making DNS requests on hosts in the FINANCE group
Translate this SPL to CQL and run it: event_simpleName=... | table ...
```

## Included hunts

1. Execution of renamed executables
2. LOLBAS binaries with network connections
3. Suspicious network connections from processes
4. PowerShell spawned from Explorer with network connections
5. RDP hijacking traces: RDP port change
6. PsLoggedOn via EID 5145 (needs Windows Security logs ingested into NG-SIEM)
