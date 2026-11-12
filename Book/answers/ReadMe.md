# Chapter Answer Keys

Sample answers for the **Review Questions** and **Practical Exercises** at the end of each chapter. One file per chapter.

These are reference answers, not the only correct ones. Your wording will differ and that is fine — what matters is whether your reasoning covers the same ground. Where an answer depends on a judgment call rather than a fact, the model answer says so and shows the reasoning rather than asserting a single right response.

## Index

| Chapter | Topic | Answer key | Matching lab |
|---|---|---|---|
| 1 | Windows Forensics in Incident Response | [Chapter01-answers.md](Chapter01-answers.md) | [Lab 01](../../Labs/Lab01/task-answers.md) |
| 2 | The Forensic Investigation Process for IR | [Chapter02-answers.md](Chapter02-answers.md) | [Lab 02](../../Labs/Lab02/task-answers.md) |
| 3 | Digital Forensics and Advanced Data Triage | [Chapter03-answers.md](Chapter03-answers.md) | [Lab 03](../../Labs/Lab03/task-answers.md) |
| 4 | Windows File System Forensics (NTFS) | [Chapter04-answers.md](Chapter04-answers.md) | [Lab 04](../../Labs/Lab04/task-answers.md) |
| 5 | Registry and Cloud Storage Forensics | [Chapter05-answers.md](Chapter05-answers.md) | [Lab 05](../../Labs/Lab05/task-answers.md) |
| 6 | Shell Items, Removable Devices, Application Artifacts | [Chapter06-answers.md](Chapter06-answers.md) | [Lab 06](../../Labs/Lab06/task-answers.md) |
| 7 | Memory Forensics | [Chapter07-answers.md](Chapter07-answers.md) | [Lab 07](../../Labs/Lab07/task-answers.md) |
| 8 | Network Forensics on Windows | [Chapter08-answers.md](Chapter08-answers.md) | [Lab 08](../../Labs/Lab08/task-answers.md) |
| 9 | Windows Event Logs | [Chapter09-answers.md](Chapter09-answers.md) | [Lab 09](../../Labs/Lab09/task-answers.md) |
| 10 | Timeline Analysis | [Chapter10-answers.md](Chapter10-answers.md) | [Lab 10](../../Labs/Lab10/task-answers.md) |
| 11 | Forensic Challenge: Unauthorized Data Exfiltration | [Chapter11-answers.md](Chapter11-answers.md) | [Lab 11](../../Labs/Lab11/task-answers.md) |
| 12 | Ransomware Incident Response | [Chapter12-answers.md](Chapter12-answers.md) | [Lab 12](../../Labs/Lab12/task-answers.md) |
| 13 | Reporting, Containment, and Recovery | [Chapter13-answers.md](Chapter13-answers.md) | [Lab 13](../../Labs/Lab13/task-answers.md) |
| 14 | Conclusion and Next Steps | [Chapter14-answers.md](Chapter14-answers.md) | — |

## What's in each file

- **Review Questions** — a model answer per question, restated so the file reads standalone.
- **Practical Exercises** — for each: *what you should end up with*, *how to get there*, and *what good looks like*. Many exercises are "do this on your lab VM," so the answer gives the expected outcome and success criteria rather than fabricated output. Where an exercise can be worked against the shipped `Data/` sets, the relevant file is named.
- **Common mistakes on this chapter** — the specific misconceptions readers actually hit on that material. Often the most useful section in the file.

## Chapter 14 is different

Chapter 14 has no Review Questions or Practical Exercises — it closes with §14.6, a structured self-assessment. `Chapter14-answers.md` is therefore a **guide to working that exercise well** rather than an answer key, and is titled accordingly. It covers what a good self-assessment looks like, how to pick focus areas honestly, and the failure modes — rating yourself on familiarity rather than demonstrated capability being the main one.

## The other answer keys in this project

Each lab carries its own two, which cover different material from these:

| File | Covers |
|---|---|
| `Labs/LabNN/task-answers.md` | The workbook-style Lab Tasks, plus a ready-to-move-on self-check and walkthrough-to-workbook bridges |
| `Labs/LabNN/walkthrough-answers.md` | The Hands-On Walkthrough steps, with the verification command for every asserted count (Labs 04–12) |

## A note on using them

Read the chapter, attempt the questions, *then* open the key. The "Common mistakes" sections are written against errors people make when they have genuinely tried the material first; read cold, they are just trivia.

Several of these keys exist because writing them exposed problems in the chapters themselves — Chapter 4 was asserting a resident-data threshold it never stated, and Chapter 6 asked readers to compare Amcache and UserAssist without ever saying plainly that Amcache is not proof of execution. Both were fixed as a result. If an answer here does not follow from the chapter text, that is a bug worth reporting.

---

*Part of [Windows Forensics for Beginners](../ReadMe.md).*
