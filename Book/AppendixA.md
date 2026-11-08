# Appendix A — Lateral Movement, Credential Abuse, and Active Directory

This appendix covers three topics the main chapters reference but do not develop: how attackers move sideways in a Windows environment, how they harvest and reuse credentials, and how to investigate Active Directory itself when you suspect a domain compromise. Treat it as a practical starting point with concrete artifacts, event IDs, and tool pointers, not an exhaustive treatment.

## A.1 Lateral Movement: What the Attacker Is Trying to Do

Lateral movement is the phase of an intrusion in which the attacker uses access on one host to gain access to others. The destination is typically a higher-value system: a domain controller, a file server, an application server, or a workstation belonging to a privileged user. The mechanism is almost always *legitimate*: a stolen credential used through a normal Windows protocol. That is what makes lateral movement hard to detect — the bytes on the wire look almost identical to authorized administrative work.

Eight techniques dominate real Windows incidents:

| Technique | Mechanism | Primary network protocol |
|---|---|---|
| **PsExec** (or `psexec.exe`-style tooling) | Connect to ADMIN$ over SMB; install a service on the remote host; service runs the payload | SMB (445), DCE/RPC for service control |
| **WMI execution** (`wmic /node` or `Invoke-WmiMethod`) | Use WMI to spawn a process on the remote host | DCE/RPC over 135 + dynamic ports |
| **Scheduled task creation** (`schtasks /s` or the `at` command) | Create a one-shot scheduled task on the remote host that runs the payload | DCE/RPC, SMB |
| **Remote service creation** (`sc \\host create`) | Create and start a service on the remote host | DCE/RPC |
| **PowerShell Remoting** (WinRM) | Open a PSSession to the remote host and run commands or scripts in it | HTTP/HTTPS on 5985/5986 |
| **RDP** (`mstsc.exe`) | Interactive Remote Desktop session | TCP 3389 |
| **DCOM execution** (`MMC20.Application`, `ShellWindows`, `ExcelDDE`) | Invoke remote method on a COM object that the attacker controls | DCE/RPC |
| **Pass-the-Hash / Pass-the-Ticket** | Authenticate to a remote host using a stolen NTLM hash or Kerberos ticket without ever having the plaintext password | NTLM or Kerberos (SMB, LDAP, etc.) |

Any of these can use any reasonable credential. The forensic question is rarely "what protocol was used?" It is "which account, from where, to where, and what did they do once they got there?"

## A.2 Source-Side Artifacts: What the Attacker's Workstation Records

A host used as a **source** for lateral movement leaves traces. Earlier chapters cover many of them, such as Prefetch, Amcache, and the Security log. The patterns below matter for lateral movement specifically.

### A.2.1 Prefetch evidence of lateral-movement tooling

Prefetch entries on the source host often include the tools used to move laterally:

- `PSEXEC.EXE-*.pf`, `PSEXESVC.EXE-*.pf`
- `WMIC.EXE-*.pf`
- `MSTSC.EXE-*.pf` (RDP client)
- `NET.EXE-*.pf`, `NET1.EXE-*.pf`
- `SC.EXE-*.pf`
- `SCHTASKS.EXE-*.pf`

PECmd output makes this visible:

```
PECmd.exe -d C:\Triage\WKSTN-221\Prefetch --csv C:\Cases\WKSTN-221\prefetch\
```

A first execution of `PsExec` on a finance workstation — particularly one with no IT admin role — is itself a finding worth following.

### A.2.2 RDP client history

`HKCU\Software\Microsoft\Terminal Server Client\Default` records recently typed RDP destinations. Each value (`MRU0`, `MRU1`, ...) is a destination the user — or attacker as that user — connected to. These values often reveal attacker reconnaissance: a workstation user typing the names of file servers, domain controllers, or jump boxes.

`HKCU\Software\Microsoft\Terminal Server Client\Servers` records the username used for each destination when the user chose to remember credentials.

### A.2.3 Bitmap cache

The RDP client stores a cache of bitmap tiles from each session in `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\`. With [bmc-tools](https://github.com/ANSSI-FR/bmc-tools), you can reconstruct portions of the screen the attacker saw on the remote host. The output sometimes includes directly readable UI elements: file names, dialog text, and fragments of the desktop.

### A.2.4 Explicit-credential events

Security event log EID 4648 (`A logon was attempted using explicit credentials`) is the canonical lateral-movement source-side event. EID 4648 fires every time the attacker supplies a credential different from the current logon, whether through `runas /user`, `net use \\host /user:...`, `psexec -u`, or any equivalent.

```
TargetUserName=domain-admin
TargetDomainName=FINANCE
TargetServerName=DC-01
ProcessName=C:\Windows\System32\cmd.exe
SubjectUserName=payroll-admin
```

A single 4648 from a finance workstation targeting a domain controller, with `domain-admin` as the target account, is one of the most forensically valuable single events in a Windows compromise.

## A.3 Destination-Side Artifacts: What the Target Host Records

### A.3.1 Logon events on the destination

Security log EID 4624 on the destination records the inbound logon. Two `LogonType` values matter most:

| LogonType | Meaning | When to be suspicious |
|---|---|---|
| **3** | Network logon (SMB, RPC) | When the source IP is unexpected or the account is privileged |
| **10** | RemoteInteractive (RDP) | When the source IP is internal but unfamiliar, or external |

Pair EID 4624 with the corresponding EID 4672 (special privileges assigned). A 4624/4672 pair on a domain controller from a workstation IP is almost always worth investigating.

### A.3.2 Service installation

Service-based lateral movement, such as PsExec or `sc create`, leaves a System log EID 7045 on the destination. PsExec copies its service binary over the `ADMIN$` share. The image path the 7045 records is therefore the *local* path where the binary lands, `%SystemRoot%\PSEXESVC.exe`, not the UNC path the attacker wrote to. Impacket's `psexec.py` and the various PsExec clones do the same thing with randomized service and binary names. Look for the shape rather than the string: a service installed minutes before other activity, with a binary directly in `C:\Windows\`, `C:\Windows\Temp\`, or `\System32\`, and a display name that is blank, gibberish, or a near-miss for a real Windows service.

### A.3.3 Scheduled task creation

Security log EID 4698 fires when a scheduled task is created. Tasks created on the remote host during lateral movement are often nameless or randomly named. Legitimate tasks have descriptive names and identifiable principals.

### A.3.4 PowerShell Remoting

WinRM-based lateral movement via PowerShell Remoting (`Enter-PSSession`, `Invoke-Command -ComputerName`) shows up in:

- `Microsoft-Windows-WinRM/Operational` — connection setup events
- `Microsoft-Windows-PowerShell/Operational` EID 4104 — script blocks executed in the session
- Security log EID 4624 LogonType 3 (network logon for the WinRM connection)

Script Block Logging (EID 4104) is particularly valuable here because, when the policy is enabled, it preserves the *content* of what the attacker ran in the session.

### A.3.5 WMI execution

WMI-based lateral movement leaves:

- `Microsoft-Windows-WMI-Activity/Operational` — events around method invocations and event consumers
- A child process under `WmiPrvSE.exe` (the WMI provider host)

The child-process pattern is the easiest to spot: a `cmd.exe` or `powershell.exe` whose parent is `WmiPrvSE.exe` is almost always remote WMI execution.

## A.4 Domain-Side Artifacts: What the Domain Controller Records

When the destination is on a domain, the domain controller logs the authentication event independently, which gives you a second corroborating source for any lateral-movement finding.

### A.4.1 Kerberos ticket events

Domain controllers running with `Audit Kerberos Authentication Service` and `Audit Kerberos Service Ticket Operations` enabled record:

| EID | Meaning | What it tells you |
|---|---|---|
| **4768** | A Kerberos TGT was requested | The user authenticated initially; the source IP is the host that requested the ticket |
| **4769** | A Kerberos service ticket was requested | The user requested access to a specific resource (Service Name field) |
| **4771** | Kerberos pre-authentication failed | Failed authentication — the Kerberos equivalent of 4625. A burst across many accounts from one source is password spraying. It is *not* the AS-REP roasting signal: that attack targets accounts with pre-authentication disabled, so it succeeds and shows up as **4768** with `PreAuthType=0` (§A.5.3) |

EID 4769 is particularly useful for tracing lateral movement because each ticket request names the *target service*, such as `cifs/filesvr-03.finance.local` or `host/dc-01.finance.local`. A user account requesting service tickets for hosts it has no business accessing is a clean lateral-movement signal.

### A.4.2 NTLM authentication

EID 4776 records successful and failed NTLM authentication attempts on whichever host validated the credential. For a domain account, that host is the DC. When a **local** account authenticates over NTLM, it is the workstation or server itself. That second case is easy to miss, and it is exactly what a local-administrator pass-the-hash produces. Check member-server Security logs for 4776 too, not only the DC's. The `Workstation` field shows the source host, and the `Logon Account` field shows which account was used. In a Kerberos-first environment, large numbers of NTLM 4776 events from a single workstation are often a compatibility fallback. They can also signal attacker tooling that prefers NTLM, such as some Pass-the-Hash chains.

### A.4.3 Account creation and group changes

| EID | Meaning |
|---|---|
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset attempt |
| 4725 | Account disabled |
| 4728 | Member added to a security-enabled global group |
| 4732 | Member added to a security-enabled local group |
| 4756 | Member added to a universal security-enabled group |

`Domain Admins`, `Enterprise Admins`, `Schema Admins`, and `Account Operators` group additions deserve immediate alerting in any environment. They are rare in normal operations and routine in compromised ones.

## A.5 Credential Abuse

### A.5.1 Pass-the-Hash

In Pass-the-Hash, the attacker authenticates using the NTLM hash of a password rather than the password itself. The attacker never learns the plaintext but can use the hash anywhere NTLM is accepted, such as SMB and RDP-RestrictedAdmin.

Detection signals:

- EID 4624 LogonType 9 (`NewCredentials`) on the source host. Logon type 9 corresponds to `runas /netonly` and similar mechanisms. Legitimate use is uncommon, and attacker use is common. The `Authentication Package` field in 4624 shows `Negotiate`/`NTLM`.
- EID 4624 LogonType 3 on the destination, with an `LmPackageName` of `NTLM V2` and a source IP / workstation that does not match the user's normal pattern.
- Memory analysis on the source can reveal Mimikatz-class tooling, LSASS access, and the harvested hashes themselves.

Mimikatz and the tools that embed it, such as Meterpreter's `kiwi` extension and Cobalt Strike's built-in `mimikatz` command, typically interact with `lsass.exe` directly. Defender for Endpoint and most modern AV products detect this access. Their logs, such as the EID in the ATP timeline and blocked-event records, are themselves evidence.

### A.5.2 Kerberoasting

Kerberoasting requests a Kerberos service ticket (TGS) for a service account that has a Service Principal Name (SPN). The attacker then takes the ticket offline and brute-forces the service account's password from its encrypted portion. Pulling the tickets requires only domain-user credentials.

Detection signals:

- EID 4769 with `Ticket Encryption Type` of `0x17` (RC4-HMAC) for a service account, especially when the account's password is set to never expire and the account has high privileges, such as `Domain Admin` membership. Modern Kerberos defaults to AES, so RC4 requests against high-value SPNs are anomalous.
- Many 4769 events for different SPNs from a single workstation in a short window — the typical pattern when an attacker enumerates SPNs and pulls tickets for all of them.

### A.5.3 AS-REP Roasting

AS-REP Roasting resembles Kerberoasting but targets accounts that have `Do not require Kerberos preauthentication` set. The attacker requests an AS-REP for the account and brute-forces it offline. Detection: EID 4768 with `PreAuthType=0` for the targeted account.

### A.5.4 DCSync

DCSync abuses the Active Directory replication API to pull password hashes from a domain controller. Those hashes include KRBTGT, the key to the kingdom for Golden Ticket attacks. The attacker needs replication permissions, which `Domain Admins` and `Enterprise Admins` have by default.

Detection signals:

- EID 4662 on a domain controller for the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` permissions. Domain controllers replicate with each other constantly, so these events are normal *between DCs* but anomalous from a workstation IP.
- Sudden replication events from a host that is not a domain controller.

The Microsoft *Directory Service* event log on the source DC also shows replication activity.

### A.5.5 Golden and Silver Tickets

A Golden Ticket is a forged TGT signed with the KRBTGT account's hash. A Silver Ticket is a forged TGS ticket signed with a service account's hash. Both bypass normal authentication and are very hard to detect in the moment.

Detection signals (after the fact):

- EID 4769 with anomalous attributes — RC4 encryption when the environment is AES-only, lifetimes longer than the domain policy permits, or `Account Name` and `Account Domain` mismatches
- Ticket lifetimes are worth checking on their own. The default domain policy allows 10 hours per ticket and 7 days for renewal. Mimikatz forges golden tickets valid for 10 years unless the operator overrides it.
- Authentication events for accounts that no longer exist, or with usernames that do not appear in any 4768 (TGT request) record — the user holds a TGS, but no 4768 shows a TGT was ever issued
- KRBTGT password rotation: when you suspect Golden Ticket compromise, rotate KRBTGT *twice*, with a delay between rotations. Replays of forged tickets stop working after the second rotation

## A.6 Active Directory Forensics: Investigating a Compromised Domain

When you suspect a domain controller is compromised, the investigation expands beyond the host artifacts in earlier chapters.

### A.6.1 NTDS.dit and SYSVOL

`NTDS.dit` is the Active Directory database file (`%SystemRoot%\NTDS\ntds.dit`). It contains all account password hashes, group memberships, and attribute data. Handle acquisition carefully: a copy of `NTDS.dit` is effectively a copy of the domain's password hashes.

Tools for NTDS analysis include [DSInternals](https://www.dsinternals.com/), Michael Grafnetter's open-source PowerShell module, and Impacket's `secretsdump.py`. The forensic questions are typically:

- Which accounts had recent password changes?
- Which accounts have weak passwords (offline crack against the hashes)?
- Are there any backdoor accounts not visible in normal AD administration tools?
- Are any account attributes anomalous, such as sIDHistory entries that should not exist or primaryGroupID changes?

`SYSVOL` (`\\domain\SYSVOL\`) holds Group Policy templates and login scripts. Attackers sometimes plant payloads in `SYSVOL` paths because every domain-joined host runs them. A scheduled forensic snapshot of `SYSVOL` content with hashes is a useful baseline to maintain.

### A.6.2 AdminSDHolder and SDProp

`AdminSDHolder` is a special AD object whose ACL the SDProp process copies every hour to all members of certain protected groups, such as Domain Admins and Enterprise Admins. Attackers sometimes modify the AdminSDHolder ACL to grant themselves persistent access. The next SDProp run propagates that access to all admin accounts.

Detection: audit `cn=AdminSDHolder,cn=System` for modification events. EID 5136 (`A directory service object was modified`) records modifications to AD objects when object access auditing is enabled.

### A.6.3 GPO and login script abuse

Group Policy Objects can run scripts at logon, startup, or via scheduled tasks. An attacker who modifies a widely-applied GPO can effectively backdoor every host in the domain.

Detection:

- `Microsoft-Windows-GroupPolicy/Operational` on hosts shows GPO application and any script execution
- AD audit events 5136 / 5137 / 5138 / 5139 / 5141 on the GPO objects in `cn=Policies,cn=System`
- File-integrity monitoring on `\\domain\SYSVOL\domain\Policies\`

### A.6.4 ACL backdoors

Attackers sometimes grant themselves persistent permissions that standard AD admin tools do not show. Examples include giving a low-privilege account full control over a high-value OU, or the right to reset a Domain Admin's password.

[BloodHound](https://bloodhound.specterops.io/) is the standard tool for mapping these relationships and finding anomalous paths. Run BloodHound periodically against a clean domain to establish a baseline. During incident response, it often surfaces ACL-based persistence the defenders did not know existed.

### A.6.5 Replication metadata

Every AD object's attributes carry replication metadata: which DC last modified the attribute, when, and the version number. Tools such as `repadmin /showobjmeta` expose this metadata. When the question is "when was this account changed and from where," replication metadata is often more reliable than event logs because it survives log rotation.

## A.7 Putting It Together: A Lateral-Movement Investigation

This worked example integrates source, destination, and domain-side artifacts:

1. **Trigger:** EID 4648 on `WKSTN-221` (source) shows the `payroll-admin` user using explicit credentials targeting `FILESVR-03`. This is unusual for a payroll workstation.

2. **Destination check:** EID 4624 LogonType 3 on `FILESVR-03` confirms the inbound network logon at the same timestamp. The source IP matches WKSTN-221.

3. **Domain check:** EID 4769 on the DC shows a service ticket request for `cifs/filesvr-03.finance.local` immediately before. The ticket encryption is AES, which is normal — no Kerberoasting signal here.

4. **Activity on destination:** EID 4688 on FILESVR-03 shows `cmd.exe` executing under the `payroll-admin` token, followed by `net.exe view` and `dir` commands traversing share contents.

5. **Source-side preparation:** Prefetch on WKSTN-221 shows recent first executions of `net.exe`, `nltest.exe`, and `arp.exe` — host reconnaissance immediately before the lateral move.

6. **Memory:** Volatility on the WKSTN-221 image shows a `powershell.exe` process whose command line included `-EncodedCommand`. The decoded command is an in-memory loader. The loaded modules include an unusual DLL not on disk.

The conclusion: the attacker compromised a finance workstation and used the user's own credentials to move to a file server. Host event logs, the domain controller, and memory document the activity on both ends. Each finding has at least two independent supporting sources. Containment can target the specific account and the two specific hosts. Remediation can focus on the loader's persistence mechanism, which further investigation still has to identify.

## A.8 Pointers for Going Deeper

The single most useful free resource for AD security and forensics is **[ADSecurity.org](https://adsecurity.org/)** by Sean Metcalf. It covers Kerberos abuse, Golden / Silver Tickets, DCSync, AdminSDHolder, and most of the techniques in this appendix in much greater depth.

For Active Directory enumeration and ACL analysis, **[BloodHound](https://bloodhound.specterops.io/)** and the SpecterOps blog are essential.

For Pass-the-Hash specifically, Microsoft's *Mitigating Pass-the-Hash and Other Credential Theft* whitepapers (versions 1 and 2, freely available) remain the most thorough public treatment.

For practical PowerShell-based AD investigation, **[PowerShell-AD-Recon](https://github.com/PyroTek3/PowerShell-AD-Recon)** and the cmdlets in the `ActiveDirectory` module (`Get-ADUser`, `Get-ADComputer`, `Get-ADReplicationAttributeMetadata`) cover most of the day-to-day work.

For hands-on practice with the lateral-movement and credential-access EID patterns covered in this appendix, the **[EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)** project ships 270+ real `.evtx` samples mapped to MITRE ATT&CK techniques and released as CC0 (public domain). The most relevant folders for this appendix sit under the *Credential Access*, *Lateral Movement*, and *Privilege Escalation* tactic directories. Parse them with `EvtxECmd` and run them through your detection logic. What your logic catches is what your environment would catch in a real intrusion.

The SANS **FOR508** (Advanced Incident Response, Threat Hunting, and Digital Forensics) and **FOR509** (Enterprise Cloud Forensics and Incident Response) courses go several layers deeper than this appendix.

---

*End of Appendix A.*

---
