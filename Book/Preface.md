# Preface

This book is for people who respond when things go wrong.

Windows forensics is one of the most important tools an incident responder has for turning "we think something is wrong" into hard facts: what happened, when, how far it went, and what you need to do next. You use it while juggling time pressure, incomplete information, and the risk of making a bad situation worse.

The focus here is practical Windows forensics for incident response, not academic theory or e-discovery. You'll learn how to:

- Triage compromised Windows systems quickly and safely
- Identify and preserve the artifacts that matter for scoping an intrusion
- Prove or disprove hypotheses using the file system, registry, shell items, event logs, memory, and network data
- Build timelines that support both technical remediation and executive reporting

The book covers legal concepts such as chain of custody and authorization, but only as much as you need to stay out of trouble during live response and evidence collection. You don't need to be a lawyer — just careful and disciplined.

Chapters 1–13 each end with a lab built from an IR perspective. The labs focus on tasks you will face on real cases:

- Imaging and triage with tight timelines
- Pulling the minimum viable artifacts to answer urgent scoping questions
- Reproducing attacker behavior in a lab so you can safely learn to recognize it in the wild

You don't need to be a seasoned examiner to start this book. If you know basic Windows administration and have done any kind of security work — EDR tuning, SOC analysis, blue-team operations, or IR — you're in the right place.

The goal is a clear, repeatable approach to acquiring, analyzing, and explaining the evidence. You should have it ready when your phone rings at 2 a.m. and someone says "the Windows servers are acting weird."

## How to Use This Book

- **If you're new to forensics:** Read sequentially. Each chapter builds on the previous one.
- **If you're already doing IR:** Skip around. Use the chapters on NTFS, registry, shell items, memory, logs, and timelines as focused refreshers.
- **If you lead IR teams:** Treat the labs as exercises you can turn into internal training scenarios.

If you don't have a Windows VM handy, the `Data/` folder at the root of this repository ships pre-parsed CSV and text outputs for each lab's scenario. You can work the analysis tasks against that data instead of generating your own, or alongside it.

The book also includes eight appendices. Five cover material the main chapters reference but do not develop. Appendix E is a quick-reference cheatsheet, Appendix F maps the content to industry certifications, and Appendix H walks through the lab VM's evidence disk:

- **Appendix A — Lateral Movement, Credential Abuse, and Active Directory.** Pass-the-Hash, Kerberoasting, DCSync, Golden/Silver Tickets, and the source/destination/domain-side artifacts that document them.
- **Appendix B — Cloud Identity and Microsoft 365 Forensics.** Entra ID sign-in and audit logs, the Unified Audit Log, OAuth consent abuse, and `MailItemsAccessed` — with concrete KQL examples.
- **Appendix C — EDR Platforms and Sysmon.** Microsoft Defender for Endpoint Advanced Hunting (KQL), CrowdStrike Falcon, SentinelOne, and Sysmon configuration plus querying.
- **Appendix D — Tooling Reference for Windows IR.** A consolidated, annotated reference for the free or freely-available tools the chapters and labs lean on: Eric Zimmerman tools, KAPE, FTK Imager, Arsenal Image Mounter, Hayabusa, HayabusaAutorun, Volatility 3, MemProcFS, Cyber Triage, SANS SIFT, Sysmon, Wireshark.
- **Appendix E — Windows Forensics Quick Reference.** A condensed one-page-density cheatsheet of artifact paths, event IDs, tool commands, and investigative questions — the case-open reference for when you don't have time to leaf through 14 chapters.
- **Appendix F — Industry and Certification Alignment.** Maps the book's content to GIAC and CompTIA certifications, MITRE ATT&CK tactics, and NIST SP 800-61 / 800-86 process phases, with suggested reading orders by goal.
- **Appendix G — Anti-Forensics and Evidence Tampering.** Timestomping, log clearing, shadow-copy deletion, secure deletion, Prefetch and journal manipulation, and LOLBin abuse, with the detection signal for each.
- **Appendix H — Adding the Evidence Disk to Your Lab VM.** Step-by-step instructions for adding the `E:` evidence disk in VMware Workstation Pro, VirtualBox, Hyper-V, UTM and Parallels Desktop, preparing it in Windows, and finding its file on the host to hash it.

---

<div align="center">

[Chapters](.) · [Labs](../Labs/ReadMe.md) · [Simulated Data](../Data/README.md) · [Quick Reference](AppendixE.md) · [Glossary](Glossary.md) · [About the Author](About.md)

</div>
