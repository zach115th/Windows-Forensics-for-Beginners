Acquisition Checklist
**Per-Host Scene Assessment, Decision-Tree Walk, and Acquisition Record — Reusable Reference**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Version:** 1.0  
**Created:** ___________________________  
**Last Updated:** ___________________________  
**Author:** ___________________________  

---

## How to Use This Checklist

One copy per host. Not one per case — per host.

1. Copy it into your case folder as `00_Admin\acquisition-<HOSTNAME>.md`
2. Fill in Section 1 **before you touch the machine**. It takes two minutes and it decides everything after it.
3. Walk Section 2 top to bottom. Do not skip a branch because the answer seems obvious.
4. Record Section 3 as you go, not afterwards. Times are UTC.
5. Section 4 is not optional. A reviewer will ask what you left behind.
6. Sign Section 6 and hand it over with the evidence.

The two rules this checklist exists to enforce: **memory before anything else on a live host**, and **a machine handed to you powered off stays powered off**. Everything else on the tree is a tradeoff you can revisit later. Those two are not.

Reference: Chapter 3 §3.7 — The Acquisition Decision Tree.

---

## Section 1 — Scene Assessment

**1.1 Identification**

| Field | Value |
|---|---|
| Case ID | |
| Hostname | |
| Asset tag / serial | |
| Make / model | |
| Assigned user | |
| Physical location | |
| Domain / workgroup / Entra-joined | |
| Responder | |
| Date/time on scene (UTC) | |
| System clock reading vs. actual UTC (offset) | |
| Authorization reference (who approved, ticket/DPA) | |

**1.2 Power state**

| Check | Finding |
|---|---|
| Power state on arrival | ☐ Powered on ☐ Powered off ☐ Sleep ☐ Hibernate ☐ Unknown |
| How was it determined (fans, LEDs, screen, remote agent) | |
| Was it powered on/off by anyone before you arrived? By whom, when? | |
| Fast Startup / hybrid shutdown likely in use? | ☐ Yes ☐ No ☐ Unknown |
| `hiberfil.sys` present, size, last-modified | |
| Screen locked or unlocked | ☐ Locked ☐ Unlocked ☐ N/A |

> If powered off: **do not power it on.** Booting fires `RunOnce` values that delete themselves, pushes new entries into Prefetch, Amcache, and ShimCache, records a boot event that may roll older records off a small log, and moves `$SI` and registry `LastWriteTime` values. Note the exception in Section 5 — it comes after the image, never instead of it.

**1.3 Logged-on user and credentials**

| Check | Finding |
|---|---|
| User logged on at console | |
| Other active sessions (RDP, terminal services) | |
| Credential available to you | ☐ Local admin ☐ Domain admin ☐ Standard user ☐ None |
| Can you elevate through a proper channel, and how long will it take? | |
| EDR agent present, healthy, and reachable from the console? | ☐ Yes ☐ No — platform: |
| If no admin: who was the credential requested from, and when? | |

> Do not attempt privilege escalation on a production host to work around an authorization gap. That is a policy problem, not a technical one. Record the constraint and collect what you can.

**1.4 Encryption state**

| Check | Finding |
|---|---|
| Encryption detected | ☐ None ☐ BitLocker ☐ Third-party ☐ Unknown |
| How detected (`manage-bde -status`, `-FVE-FS-` boot record, unreadable volume in forensic boot env.) | |
| Protection status | ☐ On ☐ Off (suspended) |
| Lock status | ☐ Unlocked ☐ Locked |
| Protector types present (TPM, TPM+PIN, recovery password, external `.BEK`, clear key) | |
| Numerical Password ID | |
| Escrow locations checked | ☐ AD ☐ Entra/Intune ☐ MBAM/ConfigMgr ☐ Ticketing ☐ Password manager ☐ Printed/`.BEK` with device |
| Key obtained? From where, and who authorised release? | |
| Removable media seized alongside the device (possible `.BEK`) | |

> Do not paste the recovery key into a report body. Record where it came from and who authorised its release.

**1.5 Network and containment state**

| Check | Finding |
|---|---|
| Network connectivity on arrival | ☐ Wired ☐ Wireless ☐ Isolated ☐ Air-gapped |
| Containment already applied (by whom, when) | |
| Is containment expected during your collection? Coordinate the timing | |
| Active connections observed before collection (if live) | |

**1.6 Business constraints**

| Check | Finding |
|---|---|
| Can this host be taken offline? Who has authority to say so? | |
| Downtime window available | |
| Storage available for the acquisition vs. disk capacity | |
| Responder and time constraints in effect | |
| Legal, regulatory, or HR sensitivities affecting scope | |

---

## Section 2 — Decision-Tree Walk

Work top to bottom. Tick the branch taken; leave untaken branches blank rather than deleting them — the untaken branches are part of the record.

**2.1 Powered on?**

- ☐ **No — powered off.** Go to 2.2.
- ☐ **Yes — powered on.** Go to 2.4.

**2.2 Powered off — encryption check first**

- ☐ Not encrypted, or key already in hand → image with forensic boot media or a hardware write-blocker
- ☐ Encrypted, key not yet located → find the key before imaging: AD, Entra/Intune, MBAM/ConfigMgr, `.BEK`, printout, ticket
  - ☐ Key found → proceed to imaging
  - ☐ **Key not recoverable** → a logical image after unlock is the only useful path, and it is unavailable on a powered-off host. Preserve the ciphertext image if storage allows, park the host, and record the constraint in Section 4 and the lessons-learned.
- ☐ Physical image taken, hash-verified
- ☐ `hiberfil.sys` collected (or absence recorded)
- ☐ `pagefile.sys` collected (or absence recorded)
- ☐ `swapfile.sys` collected (or absence recorded)

**2.3 Persistence question still unanswered after imaging?**

- ☐ No → analysis proceeds against the image. Done.
- ☐ Yes, and booting is justified → complete Section 5 before powering anything on.

**2.4 Powered on — is a user logged in?**

- ☐ No, and no working credentials → treat as powered-on but unreachable: EDR live response, or plan a lawful shutdown. Record which.
- ☐ No, but working credentials available → continue to 2.5.
- ☐ Yes → continue to 2.5.

**2.5 Local admin, or can you elevate?**

- ☐ **No** → limited collection: user-context triage plus EDR live response. Record the constraint and what it excluded (raw memory, SYSTEM/SECURITY hives, other user profiles, volume-level `$MFT`).
- ☐ **Yes** → the order below is not negotiable.

**2.6 Live collection order (admin path)**

- ☐ 1. Encryption status captured (`manage-bde -status`, `manage-bde -protectors -get`) and output saved
- ☐ 2. **Memory captured** — before triage, before anything that risks the power state
- ☐ 3. Volatile system state captured (process list, network connections, sessions, services, scheduled tasks)
- ☐ 4. Triage collection (KAPE targets or equivalent) through the running file system
- ☐ 5. Recovery key requested from escrow in parallel, if encrypted
- ☐ 6. Triage reviewed — did it answer the question?
  - ☐ Yes → stop here. Record the decision.
  - ☐ No → escalate to a full image, and record why the escalation was justified

**2.7 Physical or logical?**

- ☐ **Physical (default).** Captures every sector: allocated files, unallocated space, slack, partition gaps. Deleted data recoverable.
- ☐ **Logical.** Chosen only because physical is impossible or pointless. Tick the reason:
  - ☐ BitLocker key genuinely unrecoverable — a decrypted logical image from the live unlocked host is the only readable acquisition
  - ☐ Host cannot be taken offline; file-level acquisition through the running system or a shadow copy is the only option
  - ☐ Storage or time constraint, with the residual risk accepted and recorded
  - ☐ Other: ______________________________

> A logical image gives up deleted data, unallocated space, and file slack. If you ticked logical, say so explicitly in the report — it is the first thing a reviewer will ask about.

---

## Section 3 — Acquisition Record

**3.1 Items acquired, in order**

| # | Item acquired | Source path / device | Destination | Tool | Version | Start (UTC) | End (UTC) | Write-blocked? |
|---|---|---|---|---|---|---|---|---|
| 1 | | | | | | | | ☐ Y ☐ N ☐ N/A |
| 2 | | | | | | | | ☐ Y ☐ N ☐ N/A |
| 3 | | | | | | | | ☐ Y ☐ N ☐ N/A |
| 4 | | | | | | | | ☐ Y ☐ N ☐ N/A |
| 5 | | | | | | | | ☐ Y ☐ N ☐ N/A |
| 6 | | | | | | | | ☐ Y ☐ N ☐ N/A |

**3.2 Hashes**

| Item | Algorithm | Hash (source) | Hash (verified copy) | Verified by | Verified (UTC) | Match |
|---|---|---|---|---|---|---|
| | SHA-256 | | | | | ☐ Y ☐ N |
| | SHA-256 | | | | | ☐ Y ☐ N |
| | SHA-256 | | | | | ☐ Y ☐ N |
| | SHA-256 | | | | | ☐ Y ☐ N |

**3.3 Image and volume detail**

| Field | Value |
|---|---|
| Image type | ☐ Physical (raw/E01) ☐ Logical ☐ Triage package ☐ Memory only |
| Image format and segment size | |
| Total capacity / acquired size | |
| Volumes present, and which were acquired | |
| Acquired encrypted or decrypted? | ☐ Encrypted (ciphertext) ☐ Decrypted at acquisition ☐ N/A |
| Unlock tool, version, protector type used (working copy only) | |
| Volume shadow copies enumerated? Count and dates | |
| Original media storage location | |
| Working copy created and stored where | |

**3.4 Anomalies and interruptions**

| Time (UTC) | What happened | Effect on the evidence | Action taken |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

---

## Section 4 — What I Did NOT Collect, and Why

> Every collection decision has two sides. The negative record is the one that protects you when someone asks, months later, why a source is missing. State the risk you accepted, not just the omission.

| Not collected | Why not | Risk accepted / what this could cost the case | Recoverable later? |
|---|---|---|---|
| | | | ☐ Yes ☐ No ☐ Partly |
| | | | ☐ Yes ☐ No ☐ Partly |
| | | | ☐ Yes ☐ No ☐ Partly |
| | | | ☐ Yes ☐ No ☐ Partly |
| | | | ☐ Yes ☐ No ☐ Partly |

**Common entries worth checking against explicitly:**

- ☐ Memory — not captured because: ______________________________
- ☐ `hiberfil.sys` / `pagefile.sys` / `swapfile.sys`
- ☐ Full physical image (triage only)
- ☐ Unallocated space and file slack (logical acquisition)
- ☐ Volume shadow copies
- ☐ Other user profiles on the host
- ☐ Mailbox content (PST/OST)
- ☐ Browser cache
- ☐ Attached removable media / secondary volumes
- ☐ Cloud-only data associated with the account

**Constraints that could not be resolved on scene:**

```
[e.g. "BitLocker recovery key not present in any escrow location checked; contents
      of this host are not recoverable with the key material available."
      Name the constraint, name the escrow locations checked, and flag it for
      lessons-learned if it is a policy gap rather than a technical one.]
```

---

## Section 5 — Justified Exception Record

> Complete this section **only** if an evidence machine was powered on deliberately to observe persistence firing, or if any other deviation from the standard order was made. All four conditions must be satisfied before the machine is powered on. This is an analysis step performed on evidence already preserved — never a substitute for acquisition.

| Condition | Confirmed |
|---|---|
| 1. Pristine physical image taken and hash-verified **before** power-on | ☐ Yes — hash: |
| 2. Network isolated or sinkholed | ☐ Yes — method: |
| 3. A copy booted in a VM rather than the original hardware | ☐ Copy ☐ Original — if original, why: |
| 4. Decision, justification, and exact boot time documented | ☐ Yes |

| Field | Value |
|---|---|
| Question the image left unanswered | |
| Decision made by / approved by | |
| Exact boot time (UTC) | |
| Memory captured at boot? Tool, version, hash | |
| Observed result (process launched, injection, config decrypted, network destination) | |

**Statement of limits:** this capture demonstrates that the persistence mechanism executes and shows what it does when it runs. It does **not** recover the attacker's prior interactive session or any volatile state from before the shutdown. Every artifact timestamp after the boot time above is attributable to the responder, not to the attacker.

---

## Section 6 — Sign-Off and Handover

**6.1 Responder sign-off**

| Field | Value |
|---|---|
| Responder name and role | |
| Signature | |
| Date/time completed (UTC) | |
| Statement | I performed the acquisitions recorded in Section 3, in the order recorded, using the tools and versions listed. The omissions in Section 4 were deliberate and are recorded with the reasoning applied at the time. |

**6.2 Evidence handover**

| Item | Released to | Organisation | Date/time (UTC) | Method (hand-carry, courier, secure transfer) | Receiving signature |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |

**6.3 Chain of custody**

| Check | Status |
|---|---|
| Chain of custody form opened for each item | ☐ Yes ☐ No |
| Hashes recorded on the custody form | ☐ Yes ☐ No |
| Originals write-protected and stored | ☐ Yes ☐ No — location: |
| Working copies created and hash-verified against originals | ☐ Yes ☐ No |
| Case notes updated with a pointer to this checklist | ☐ Yes ☐ No |

**6.4 Open items for the next responder**

```
[Anything the next person needs to know before they touch this evidence: pending
 escrow requests, keys expected, an image still verifying, a constraint that may
 lift, a host still live and awaiting a containment decision.]
```

---

*Acquisition Checklist — Windows Forensics for Beginners*  
*Version 1.0 — One copy per host. Update the master whenever an engagement teaches you a field you wished you had recorded.*
