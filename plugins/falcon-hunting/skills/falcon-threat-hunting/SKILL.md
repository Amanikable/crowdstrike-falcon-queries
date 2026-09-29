---
name: falcon-threat-hunting
description: Run threat hunts against CrowdStrike Falcon telemetry through the falcon-mcp server. Use when the user asks to hunt in Falcon, run or translate a Falcon/Splunk (SPL) hunting query, search Next-Gen SIEM (NG-SIEM) with CQL, or look for renamed executables, LOLBins making network connections, suspicious process network activity, PowerShell spawned by Explorer, RDP port changes, or PsLoggedOn activity.
---

# Falcon threat hunting

This skill runs hunts from the `crowdstrike-falcon-queries` collection against a live
Falcon tenant. It uses the `falcon-mcp` server that ships with this plugin. The original
hunts were written in Splunk SPL for the old Falcon Event Search. Today the same data
lives in Next-Gen SIEM, which uses CQL (CrowdStrike Query Language). The ready-to-run CQL
versions are in [references/hunts.md](references/hunts.md).

## Workflow

1. **Check the connection.** Call `falcon_check_connectivity`. If it fails, tell the user
   to set `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET` and (outside US-1)
   `FALCON_BASE_URL` before starting Claude Code. The API client needs the
   `NGSIEM:read` and `NGSIEM:write` scopes to run searches.
2. **Pick the hunt.** Match the request to a hunt in `references/hunts.md`. If the user
   brings their own SPL, translate it using the rules below.
3. **Read the CQL guide before writing new CQL.** Read the
   `falcon://ngsiem/search/cql-guide` MCP resource whenever you write CQL that isn't
   copied verbatim from `references/hunts.md`. Zero-row and error responses from
   `falcon_search_ngsiem` also include the guide in their `cql_guide` field.
4. **Keep the time window tight.** Call `falcon_search_ngsiem` with `query_string`,
   an ISO 8601 `start` (default to the last 24 hours unless the user says otherwise),
   and `repository="search-all"` unless the user names a view. Widen the window only
   when a hunt needs it. For example, parent/child correlation on long-running system
   processes can need several days.
5. **Check what actually ran.** CQL doesn't return parser errors. A query it can't parse
   still runs, as free-text filters. Compare `job.parsed_query` with the query you
   meant to run. On zero rows, look at `job.processed_events`: a value above zero is a
   real negative, while zero usually means a syntax or field-name problem.
6. **Report.** Summarize the findings: host, process, command line, and why each hit
   matters. Suggest pivots, such as `falcon_search_hosts` for host context,
   `falcon_search_detections` for related alerts, or `falcon_search_indicators` for IOC
   lookups. Treat hits as leads to investigate, not as confirmed compromise.

## Translating SPL to CQL

| SPL | CQL |
| --- | --- |
| `event_simpleName="ProcessRollup2"` | `#event_simpleName=ProcessRollup2` |
| `FileName="powershell.exe"` | `FileName=/^powershell\.exe$/i` (case-insensitive) |
| `field="*\RDP-Tcp"` | `field=/\\RDP-Tcp$/i` |
| `*_decimal` fields (`TargetProcessId_decimal`) | Drop the suffix (`TargetProcessId`) |
| `RemoteIP`, `RemotePort_decimal` | `RemoteAddressIP4`, `RemotePort` |
| `timestamp` | `@timestamp` |
| `rename a as b` | `b := a` |
| `table a b c` | `table([a, b, c])` or `select([a, b, c])` |
| `stats count by a` | `groupBy([a], function=count())` |
| `head 10` | `head(10)` (oldest first) or `tail(10)` (newest first) |
| `join f [search ...]` | See the correlation pattern below |

### Correlation pattern (replaces `rename | join [subsearch]`)

SPL subsearch joins are slow and truncate results. In CQL, pull both event types in one
pass, normalize the join key with `case`, then use `groupBy` to keep only keys that
appear in both event types:

```
#event_simpleName=/^(ProcessRollup2|DnsRequest)$/
| case {
    #event_simpleName=ProcessRollup2 | falconPID := TargetProcessId ;
    #event_simpleName=DnsRequest     | falconPID := ContextProcessId ;
  }
| groupBy([aid, falconPID], function=[
    count(#event_simpleName, distinct=true, as=eventTypes),
    collect([ComputerName, FileName, CommandLine, DomainName])
  ])
| eventTypes > 1
```

`TargetProcessId` is unique per sensor (`aid`), so always group on `aid` and the
process ID together. Add extra filters for either event type inside its `case` branch.

## Safety

The plugin starts `falcon-mcp` with `FALCON_MCP_READ_ONLY=true` by default, so it
doesn't register any tool that changes tenant state. Hunting never needs write access.
If the user turns read-only mode off, confirm with them before any containment,
exclusion, IOC or policy change.
