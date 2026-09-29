# Hunt catalog (CQL)

These are the NG-SIEM (CQL) versions of the SPL hunts in this repository's
[README](https://github.com/amanikable/crowdstrike-falcon-queries#readme). Run each one with `falcon_search_ngsiem`. Field names
follow the Falcon endpoint data in NG-SIEM. If a hunt returns zero events scanned, check
the field names against a sample event (`#event_simpleName=<type> | head(1)`).

## 1. Execution of renamed executables

Finds executables that were renamed (`NewExecutableRenamed`) and then run
(`ProcessRollup2`) under the new name. Inspired by Red Canary's research on
"detecting the unknown."

```
#event_simpleName=/^(NewExecutableRenamed|ProcessRollup2)$/
| case {
    #event_simpleName=NewExecutableRenamed | ImageFileName := TargetFileName ;
    #event_simpleName=ProcessRollup2 ;
  }
| groupBy([aid, ImageFileName], function=[
    count(#event_simpleName, distinct=true, as=eventTypes),
    collect([ComputerName, SourceFileName, CommandLine])
  ])
| eventTypes > 1
```

## 2. Living-off-the-land binaries with network connections

Finds LOLBAS binaries that make DNS requests. The binary list comes from the
[LOLBAS project](https://github.com/LOLBAS-Project/LOLBAS). Extend the regex to add
binaries.

```
#event_simpleName=/^(ProcessRollup2|DnsRequest)$/
| case {
    #event_simpleName=ProcessRollup2 FileName=/^(atbroker|bash|bitsadmin|certutil|cmd|cmstp|control|cscript|csc|dfsvc|diskshadow|dnscmd|esentutl|eventvwr|expand|extexport|extrac32|findstr|forfiles|ftp|gpscript|hh|ie4uinit|ieexec|infdefaultinstall|installutil|jsc|makecab|mavinject|mmc|msconfig|msdt|mshta|msiexec|odbcconf|pcalua|pcwrun|presentationhost|print|regasm|regedit|register-cimprovider|regsvcs|regsvr32|reg|replace|rpcping|rundll32|runonce|runscripthelper|schtasks|scriptrunner|sc|syncappvpublishingserver|verclsid|wab|wmic|wscript|wsreset|xwizard)\.exe$/i
      | falconPID := TargetProcessId ;
    #event_simpleName=DnsRequest | falconPID := ContextProcessId ;
  }
| groupBy([aid, falconPID], function=[
    count(#event_simpleName, distinct=true, as=eventTypes),
    collect([ComputerName, ImageFileName, CommandLine, DomainName])
  ])
| eventTypes > 1
```

## 3. Suspicious network connections from processes

Ties outbound IPv4 connections to the process and user that made them. The original SPL
matched every connection. This version drops private, loopback and link-local
destinations to cut noise, and ranks results by how many hosts made the same connection.
Rare combinations float to the top.

```
#event_simpleName=/^(ProcessRollup2|NetworkConnectIP4)$/
| case {
    #event_simpleName=ProcessRollup2 | falconPID := TargetProcessId ;
    #event_simpleName=NetworkConnectIP4
      | !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
      | falconPID := ContextProcessId ;
  }
| groupBy([aid, falconPID], function=[
    count(#event_simpleName, distinct=true, as=eventTypes),
    collect([ComputerName, ImageFileName, UserName, UserSid, RemoteAddressIP4, RemotePort])
  ])
| eventTypes > 1
| groupBy([ImageFileName, RemoteAddressIP4, RemotePort], function=count(aid, distinct=true, as=hostCount))
| sort(hostCount, order=asc, limit=200)
```

## 4. Suspicious PowerShell spawned from Explorer with network connections

Finds PowerShell started by `explorer.exe` (a user double-clicking or using Run) that
then made DNS requests. The SPL needed a nested double join. In NG-SIEM,
`ProcessRollup2` carries `ParentBaseFileName`, so one correlation is enough.

```
#event_simpleName=/^(ProcessRollup2|DnsRequest)$/
| case {
    #event_simpleName=ProcessRollup2 FileName=/^(powershell|pwsh)\.exe$/i ParentBaseFileName=/^explorer\.exe$/i
      | falconPID := TargetProcessId ;
    #event_simpleName=DnsRequest | falconPID := ContextProcessId ;
  }
| groupBy([aid, falconPID], function=[
    count(#event_simpleName, distinct=true, as=eventTypes),
    collect([ComputerName, ImageFileName, CommandLine, DomainName])
  ])
| eventTypes > 1
```

## 5. Threat Hunting #1: RDP hijacking traces, part 1 (RDP port change)

Finds changes to the RDP listener port (`...\WinStations\RDP-Tcp\PortNumber`). Inspired
by MENASEC's RDP hijacking research. `LastLoggedOnUser` and `LastLoggedOnSAMUser`
changes don't count as system config updates, so Falcon doesn't record them under
`RegSystemConfigValueUpdate`.

```
#event_simpleName=RegSystemConfigValueUpdate RegObjectName=/\\RDP-Tcp$/i RegValueName=PortNumber
| NewRDPPort := RegNumericValue
| table([@timestamp, ComputerName, NewRDPPort])
```

## 6. Threat Hunting #2: PsLoggedOn via EID 5145

Inspired by MENASEC's PsLoggedOn research. PsLoggedOn reads a remote host's `winreg`
named pipe over `IPC$`, which Windows logs as Security event 5145. Falcon sensor
telemetry doesn't contain this event (the original SPL found nothing either). It shows
up only when Windows Security logs are ingested into NG-SIEM through a third-party
connector.

Field names depend on the connector, so start with free text in the `third-party`
repository, then refine the query using the fields that come back:

```
"5145" "IPC$" "winreg"
| head(20)
```
