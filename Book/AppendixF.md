# Appendix F — Industry and Certification Alignment

This appendix maps the book's content to the certifications and frameworks practitioners are most likely to encounter, so you can see where the material lands relative to external benchmarks. The Windows IR discipline has a well-developed certification ecosystem and a recognized industry framework.

The mappings below are **suggestive, not authoritative**. Exam objectives change, vendors update syllabi, and community frameworks evolve. Confirm each mapping against the live source before you use it for exam-prep planning. The mappings help you locate yourself in the broader landscape. They do not substitute for the official study guides.

---

## F.1 Certification Map

### SANS / GIAC

| Certification | Coverage | Where in this book |
|---|---|---|
| **GCFE** — GIAC Certified Forensic Examiner | Host-based Windows forensics: registry, shellbags, prefetch, browser, email | Chapters 4, 5, 6 + Labs 04–06 |
| **GCFA** — GIAC Certified Forensic Analyst | Advanced IR + memory + timeline analysis + APT methodology | Chapters 7, 9, 10, 11 + Appendix A + Labs 07, 09, 10, 11 |
| **GNFA** — GIAC Network Forensic Analyst | Packet, flow, NetFlow, NSM, proxy/DNS, decoding network protocols | Chapter 8 + Lab 08 + parts of Lab 11 |
| **GREM** — GIAC Reverse Engineering Malware | Malware triage in memory; PE basics; behavioral analysis | Chapter 7 partial overlap (memory side only); GREM proper is out of scope |
| **GCIH** — GIAC Certified Incident Handler | The IR process, scoping, containment, communication | Chapters 1, 2, 3, 12 + Appendix A |

### CompTIA

| Certification | Coverage | Where in this book |
|---|---|---|
| **Security+** | Foundational concepts including basic incident response | Chapter 1, parts of Chapters 2, 3, 9 |
| **CySA+** — Cybersecurity Analyst | Threat detection, log analysis, IR fundamentals | Chapters 2, 3, 8, 9, 10 + Appendix C |
| **CASP+** / **SecurityX** | Advanced enterprise security including forensic analysis | Chapter 11, parts of 7, 8 + Appendices A, B |

### Vendor and community

| Credential | Coverage | Where in this book |
|---|---|---|
| **AccessData ACE / Magnet AXIOM certifications** | Tool-specific certifications | Not covered (tool-specific); methodology in Chapters 4–7 is transferable |
| **Cellebrite CCO / CCPA** | Mobile forensics | Out of scope for this book |
| **CFCE — Certified Forensic Computer Examiner** (IACIS) | Computer forensics methodology | Chapters 3, 4, 5, 6 + Lab 03 |
| **EnCE — EnCase Certified Examiner** | EnCase-specific | Not covered (commercial tool); the underlying NTFS/registry concepts are in Chapters 4–5 |
| **Volatility Foundation training** | Memory forensics with Volatility | Chapter 7 + Appendix D §D.8 + Lab 07 |

---

## F.2 MITRE ATT&CK® Coverage

The book references ATT&CK throughout. These ATT&CK tactic IDs receive the most coverage:

| Tactic | Chapters that cover it |
|---|---|
| TA0001 Initial Access | Chapters 9 (4624/4625), 11 (capstone), 12 (RDP brute force) |
| TA0002 Execution | Chapters 6, 7, 9, 12 |
| TA0003 Persistence | Chapter 5 §5.2, Chapter 12 §12.2.3, Appendix A |
| TA0004 Privilege Escalation | Chapter 9, Appendix A |
| TA0005 Defense Evasion | Chapter 4 (timestomping), 9 (log clearing 1102), 12 §12.2.7, Appendix C (Sysmon), Appendix G (whole appendix) |
| TA0006 Credential Access | Appendix A (LSASS, Kerberoasting, DCSync) |
| TA0007 Discovery | Chapters 6, 9; capstone |
| TA0008 Lateral Movement | Appendix A (PsExec, WMI, RDP, PSRemoting) + Chapters 11, 12 |
| TA0009 Collection | Chapters 11, 12 §12.5.2 (staging), Appendix B (M365) |
| TA0010 Exfiltration | Chapters 8, 11, 12 §12.5 |
| TA0011 Command and Control | Chapters 8 (network), 7 (memory netscan) |
| TA0040 Impact | Chapter 12 (encryption, shadow copy destruction, backup targeting), Chapter 13 §13.5 (recovery) |

For each tactic, the book identifies the **artifacts** that detect the corresponding techniques, not the techniques themselves. ATT&CK gives the attacker's perspective. This book gives the responder's perspective on the same events.

The hunt-pack workflow in Chapter 9 and Lab 09 uses Sigma rules with ATT&CK mapping. [Hayabusa](https://github.com/Yamato-Security/hayabusa) and the [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) datasets are the operational bridge.

---

## F.3 NIST Framework Cross-Reference

### NIST SP 800-61 (Computer Security Incident Handling Guide)

> **Note on revisions:** Revision 3 (April 2025) supersedes r2 and restructures the guidance around the CSF 2.0 Functions rather than the four-phase lifecycle below. The r2 phases remain the mental model most practitioners and most exams still use, so the mapping is still useful. Cite Rev 3 if you are writing against current NIST guidance.

| 800-61 phase | Chapter coverage |
|---|---|
| Preparation | Chapter 1 + Appendix D (tooling) |
| Detection and Analysis | Chapters 2, 3, 7, 8, 9 |
| Containment, Eradication, Recovery | **Chapter 13** + Chapters 2, 12 |
| Post-Incident Activity | **Chapter 13** §13.6 + Chapter 14 + reflection sections throughout |

### NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response)

| 800-86 element | Chapter coverage |
|---|---|
| Collection | Chapter 3 + Lab 03 |
| Examination | Chapters 4–7, 9 |
| Analysis | Chapters 7, 8, 9, 10 + Appendix A |
| Reporting | **Chapter 13** + Chapter 11 §11.6 + capstone deliverables |

---

## F.4 Where the Book Doesn't Reach

These are the book's gaps, stated explicitly so your study plan stays honest:

- **Reverse engineering / malware analysis** — Chapter 7 covers memory triage, not RE proper. For GREM-equivalent depth, follow up with [Practical Malware Analysis](https://nostarch.com/malware) and PE-focused tooling.
- **Mobile (iOS / Android) forensics** — Entirely out of scope. Acquisition, file systems, and artifacts differ enough that bundling them in would dilute both.
- **macOS / Linux endpoint forensics** — Out of scope as primary topics. Linux server forensics (`auth.log`, `journalctl`, `aide`, `auditd`) is a natural companion and is well-covered in SANS FOR577 and other dedicated resources.
- **Network IDS / IPS engineering** — Chapter 8 covers the *responder's* use of network evidence. Engineering detection content (Snort/Suricata signatures, Zeek package development) is adjacent and not covered.
- **Cloud-side IR (AWS / GCP / Azure beyond M365)** — Appendix B covers M365 / Entra ID. AWS CloudTrail, Azure Activity Logs, and GKE/EKS forensics are adjacent and not covered.
- **Legal / courtroom testimony** — Chapter 1 covers chain of custody. Expert-witness preparation, deposition technique, and rules of evidence are out of scope.
- **Disk encryption recovery** — The book mentions BitLocker / FileVault recovery in passing but does not develop it. It is specialized work for either commercial tooling or vendor-specific recovery procedures.

If your goal is to pass a specific certification exam, treat this book as one input among several. The official study guides and the GIAC/CompTIA/vendor practice exams remain authoritative.

---

## F.5 Suggested Reading Order by Goal

| Your goal | Recommended chapter / lab order |
|---|---|
| GCFE prep | Ch 1, 2, 3, 4, 5, 6 → Labs 01–06 → Appendix E |
| GCFA prep | All of the above + Ch 7, 9, 10, 11 → Labs 07, 09, 10, 11 → Appendices A, C |
| GNFA prep | Ch 8 + Lab 08 → Appendix C → Appendix E §E.6 |
| New IR analyst — first 30 days | Ch 1, 2, 3 + Appendix D + Lab 01 → Lab 02 → Lab 03 |
| Build a hunt program | Ch 9 + Lab 09 + Appendix C + EVTX-to-MITRE-Attack |
| Investigate exfiltration | Ch 8, 11 + Labs 08, 11 + Appendix B |
| Memory analysis fluency | Ch 7 + Lab 07 + Appendix D §D.8/§D.9 + Volatility Foundation training |
| Build out home lab | Lab 01 + Appendix D (full) + CONTRIBUTING.md "new dataset" section |

The book is sequential by design, but returning to earlier chapters with the mental model the later ones build pays off. That is especially true of Chapter 4 (NTFS) and Chapter 9 (event logs), which underlie almost every other artifact discussion.

---

*End of Appendix F.*
