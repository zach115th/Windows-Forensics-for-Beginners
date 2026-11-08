# Lab 06 — Task Answer Key

*Sample answers for the workbook-style Tasks in `Labs/Lab06/ReadMe.md`. These are reference answers, not the only correct answers — your wording may legitimately differ. The reasoning matters more than the prose. For the Hands-On Walkthrough at the end of the lab, see `walkthrough-answers.md` in the same folder.*

---

## Task 1 — Identify Which Artifacts Answer Which Questions

**Sample table:**

| Investigative Question | Best Artifact(s) to Check First | Why |
|---|---|---|
| Was a suspicious EXE likely executed? | Prefetch, Amcache, SRUM (process column) | Prefetch is the textbook execution artifact; Amcache catches binaries that Prefetch missed; SRUM corroborates with resource usage |
| Did the user likely open a sensitive document? | LNK files, Jump Lists, RecentDocs | LNK and Jump Lists are tied to specific application opens; RecentDocs is the per-extension MRU |
| Was a folder on removable media browsed in Explorer? | Shellbags | Shellbags record folder navigation and survive after the underlying volume is gone |
| Which program opened a particular file? | Jump Lists | Automatic Jump Lists are indexed per-AppId, so the application is named directly |
| Did a process use unusual network resources? | SRUM (network table), EDR network telemetry | SRUM ties bytes-on-wire to the process; EDR adds remote endpoints |
| Was a specific archive or document accessed from Downloads? | LNK files, Jump Lists, RecentDocs | All three index Downloads paths; LNK gives exact target path |
| Was a removable device likely involved in file staging? | Shellbags + LNK files with matching volume serial + USBSTOR | Device identification, folder browsing, and per-file opens all need to align |
| Did the user interact with a suspicious program through the GUI? | UserAssist | UserAssist is the precise per-user record of GUI-launched programs |

**Six added questions (sample):**

| Investigative Question | Best Artifact(s) to Check First | Why |
|---|---|---|
| Was a macro-enabled Office document opened from an email or download? | Office MRU, Jump Lists (Word/Excel), RecentDocs | Office's own MRU plus Jump Lists tie the doc to the application |
| What was the parent application when a PowerShell session started? | Prefetch (referenced strings), Amcache, SRUM, EDR ProcessCreate | Prefetch lists strings/files referenced at run time; EDR is more authoritative |
| Did the user reach the delivery URL via email or via a search engine? | Browser history `ReferrerURL` column, with `Transition` | `Transition` records how the page was reached, such as typed or link, but not where a click started. `ReferrerURL` names the source page. On FIN-WS23 both delivery visits read `Transition=link`, and the 06:31:42 visit's referrer is `https://outlook.office365.com/mail/inbox`, which points to email |
| Was a USB device explored or was it only plugged in? | Shellbags for the drive letter; LNKs with matching volume serial | USBSTOR shows connection only; the shell artifacts show interaction |
| Did the user save a file *to* a removable device? | OpenSavePidlMRU under the USB drive letter; USN Journal | Save dialogs and USN entries on the USB volume catch the write |
| Was an archive extractor run against a specific archive? | Prefetch for `7zg.exe` / `7z.exe` / `WinRAR.exe` (referenced strings show archive path), Jump Lists | Archive extractors leave path strings in Prefetch and recent items in their own Jump Lists |

**Q1:** Why is this question-to-artifact approach better than parsing everything at once?

Starting from the question defines what "useful" means and tells you when to stop. Parsing every artifact on every box instead produces a wall of output that no analyst can read in a useful time. You also avoid finding something interesting in a tangential artifact and chasing it before you answer the question that matters to leadership. Triage is about ordering: questions first, artifacts second.

**Q2:** Why do some questions require multiple artifacts rather than one?

Each artifact has a partial view. Prefetch tells you a binary ran but not what document it opened. Jump Lists tell you a document was opened but not whether the binary that opened it was malicious. UserAssist tells you the user double-clicked something but not what happened after. The strongest IR claims need at least two independent artifacts converging on the same event. A Prefetch entry for a binary, an Amcache row with its SHA-1, and a Jump List entry showing the macro-enabled document that triggered it form a chain that is much harder to dispute than any single artifact.

**Q3:** Why is "evidence of execution" different from "evidence of file presence"?

A file's presence on disk, shown by an MFT entry or other NTFS metadata, proves only that the file was created. It does not prove anyone ran it. Execution evidence requires a Prefetch trace, an Amcache row indicating execution-related metadata, a UserAssist count, a Security 4688 / Sysmon 1 event, or an EDR ProcessCreate. The distinction matters because malware analysis takes a different posture when the binary only landed on disk than when it ran. Adversaries often drop binaries that are quarantined or never executed.

---

## Task 2 — Review LNK Files and Jump Lists

**Sample table:**

| Artifact Type | What It Can Reveal | Why It Matters | Limitation |
|---|---|---|---|
| LNK files | Target path, target size, target modified time, volume serial, hostname (for network shares), MAC address (some versions) | Record of a file the user opened — survives even after the original file is deleted | Need the LNK to have been created in the first place; some programs do not generate them |
| Automatic Jump Lists | Per-AppId list of recently used items, with timestamps | Names the application that opened each file (Word, Excel, Notepad++, etc.) | Limited number of entries per app; oldest entries roll off |
| Custom Jump Lists | Pinned items and application-defined tasks | Useful when the user has pinned specific files or sites | Less common; not every application produces them |

**Q1:** Why are LNK files useful when the original file has been deleted or moved?

LNK files are independent of their targets. They live in `%AppData%\Microsoft\Windows\Recent\` and elsewhere, and they store the target path, target size, target timestamps, and the serial of the target's volume at the time the LNK was created. When the original target file is deleted or the USB drive is removed, the LNK persists. Its volume serial identifies the volume the file was opened from, not the physical device. A volume serial is assigned at format time and is unrelated to the USBSTOR device serial (Chapter 6 §6.5.1). In the FIN-WS23 scenario, the two LNK files with `VolumeSerialNumber=B4D7-22A1` place their targets on the `F:` volume. System EID 98 at 09:14:12 maps volume `{b4d722a1-1142-11ef-8a4f-0c9d92841421}` to `F:`, and `usbstor.csv` assigns that GUID to the SanDisk serial. That chain, not the volume serial alone, is the evidence that files were opened from that USB.

**Q2:** Why do Jump Lists help tie a file to a specific application?

Jump Lists are indexed by ApplicationID, and the AppId hash uniquely identifies which application owns the list. When you see `Q4_Vendor_Review.docm` in the jump list for the Microsoft Word AppId, you know Word opened that document, not just that the document was on the system. That ties the file-open event to a specific process. The tie matters when the question is whether a macro-enabled document was opened in Word, which makes macro execution likely, or in a viewer that does not run macros, which makes execution unlikely.

**Q3:** Why should you be careful not to overstate what a shortcut proves by itself?

A LNK file can be created by Explorer auto-shortcut behavior, by a user dragging a file into a folder, by a program enumerating files, or by the user actually opening the target. The LNK alone confirms only that *something* caused it to exist and that the target path was reachable at that time. To claim the user opened the file, you typically need a corroborating Jump List entry, a RecentDocs entry, or an application MRU entry. Always describe a LNK as "evidence consistent with the file being opened," not as proof of an open.

**Sample items-of-interest table (FIN-WS23):**

| Item of Interest | Path or File | Artifact Source | Why It Would Matter |
|---|---|---|---|
| Suspicious EXE in Downloads | `C:\Users\j.smith\Downloads\dl.exe` | Amcache (path + SHA-1), Prefetch | Confirmed downloaded and executed once |
| Sensitive document | `Q4_Vendor_Review.docm` (macro-enabled) | Jump List (Microsoft Word AppId) | Word opened a macro-enabled document immediately before the loader ran |
| Removable-media path | `F:\Vendors\Confidential\` | Shellbags | User browsed sensitive folder tree on the USB |
| Network share path | (sample) `\\fileserver01\Vendor_Contracts\` | Shellbags / TypedPaths | Suggests reach into shared content during the same window |

**Four added items (sample):**

| Item of Interest | Path or File | Artifact Source | Why It Would Matter |
|---|---|---|---|
| Email attachment | `Q4_Vendor_Review.docm` from a delivery URL | Browser downloads + Jump List | Anchors the delivery chain |
| LNK referencing the USB | LNKs with `VolumeSerialNumber=B4D7-22A1` | LNK files in Recent | Binds each file to the `F:` volume. EID 98 and USBSTOR then tie that volume to the SanDisk |
| PowerShell host invoked from Word | `WINWORD.EXE` → `powershell.exe` | Prefetch referenced strings; EDR ProcessCreate (Sysmon EID 1) | Classic macro-loader pattern |
| Archive extraction | `7zg.exe` recent items | Prefetch + Jump List | Implies a packaged tool or payload was unpacked |

---

## Task 3 — Review Prefetch and Amcache

**Sample table:**

| Artifact | What It Can Reveal | Why It Matters in IR | Limitation |
|---|---|---|---|
| Prefetch | Executable name, last-run time, run count, files/strings referenced at execution | Most direct evidence-of-execution artifact on Windows clients; the first place responders check | Off by default on some server SKUs; only the 8 most recent runs are timestamped; 128/1024 file limit depending on Windows version |
| Amcache | Path, SHA-1, file size, PE compile time, signing context for binaries that have run or been registered with AppCompat | Catches binaries that Prefetch missed and gives you the SHA-1 directly | Servers run AppCompat differently; some entries are program-installer registrations, not executions |

**Q1:** Why is Prefetch often one of the first artifacts responders check for execution?

Prefetch is fast to parse and unambiguous: an entry means a binary executed on this host. It gives you the executable name, last-run time, and run count at once. A binary in Prefetch with `RunCount=1` and a recent `LastRun` is the textbook "new on this host" signal, which is exactly the case for `DL.EXE` on FIN-WS23. Prefetch also lists referenced files and strings, which can show the working directory, the loaded DLLs, and sometimes the document that triggered the run.

**Q2:** Why is Amcache useful even when Prefetch is unavailable or incomplete?

Amcache covers a broader population of binaries than Prefetch. Application Experience maintains it in `AmCache.hve` under `C:\Windows\AppCompat\Programs\`, and it records SHA-1, path, size, and signing information for binaries registered with AppCompat. On a server SKU where Prefetch is off, Amcache may be the only host-side execution-adjacent artifact. The SHA-1 is what you submit to threat intel. The path tells you whether the binary was installed under Program Files or downloaded to a user-profile path.

**Q3:** Why should a responder avoid claiming too much from one execution artifact alone?

A Prefetch entry confirms a binary's name was loaded but does not say what the binary did. An Amcache entry can sometimes reflect registration rather than execution. An adversary can tamper with both on a sufficiently compromised host. The defensible claim is "evidence consistent with execution on this date/time," not "the malware ran successfully and accomplished X." The second claim needs network, EDR, or memory corroboration.

**Sample focused-review table:**

| Suspected Program or File | Artifact to Check | What Finding Would Increase Concern |
|---|---|---|
| `tool.exe` in Downloads | Prefetch, Amcache | Single-run, recent LastRun, SHA-1 with poor reputation, path in user-profile Downloads |
| `runme.bat` in ProgramData | Prefetch for `cmd.exe` referenced strings, Amcache for cmd.exe runs | `cmd.exe` Prefetch referencing the bat file path; SRUM showing recent process activity |
| PowerShell | Prefetch for `powershell.exe`, Amcache | Multiple runs with recent timestamps; PSReadLine console history; ScriptBlock 4104 events |
| Archive extractor or scripting tool | Prefetch for `7z.exe`, `7zg.exe`, `winrar.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe` | Recent run with referenced strings pointing to a suspicious archive or script path |

**Five added entries (sample):**

| Suspected Program or File | Artifact to Check | What Finding Would Increase Concern |
|---|---|---|
| LOLBin (`rundll32.exe`, `regsvr32.exe`, `mshta.exe`) | Prefetch, Amcache, command-line via EDR or Sysmon 1 | Recent execution with arguments pointing into AppData or Temp |
| `certutil.exe` | Prefetch, Sysmon/4688 command-line | `-urlcache -split -f http://...` pattern is high-confidence dropper behavior |
| `wmic.exe` / `wmiprvse.exe` | Prefetch, Sysmon | WMIC process creation can indicate lateral movement or persistence |
| Browser binaries (`chrome.exe`, `msedge.exe`) | Prefetch run count and last-run | Used to confirm browser usage when correlating with browser-history evidence |
| Custom-named binary in `C:\Users\Public\` | Prefetch, Amcache | Anything in `C:\Users\Public\` that is not a Microsoft binary deserves review |

---

## Task 4 — Review SRUM and UserAssist

**Sample table:**

| Artifact | What It Helps Answer | Why It Matters | Limitation |
|---|---|---|---|
| SRUM | Per-process resource usage (bytes sent/received, CPU, energy) over the recent past, with a network table that ties bytes to a process | Catches processes that did real network work, including binaries that no longer exist on disk | ~30–60 days retention; not always present on server SKUs; binned per hour |
| UserAssist | Which programs the specific user has interactively launched, with launch count and last-run timestamp | Confirms user GUI interaction with a specific binary | GUI launches only (not command-line or service-launched programs); ROT13-encoded values |

**Q1:** Why is SRUM especially useful in exfiltration or beaconing investigations?

SRUM's `Application Resource Usage` and `Network Data Usage` tables tie *bytes-on-wire* to a specific binary path, which gives you per-process attribution without EDR. If `update.exe` shows 2.4 MB inbound in a single SRUM bin, that volume is unusual for an "update" binary and merits review. SRUM is also one of the few host-side artifacts that retains evidence for weeks. An exfiltration that happened 10 days ago and was cleaned from logs may still show up there.

**Q2:** Why is UserAssist helpful for GUI-driven user behavior but incomplete for execution analysis overall?

UserAssist records only launches initiated through the Explorer shell, such as double-clicks, Start-menu launches, and file-association openings. It misses anything started by a service, by `cmd.exe`, by PowerShell, by Task Scheduler, or by another process. UserAssist can confirm "the user did this with the mouse," but it cannot tell you about scripted or headless execution. Treat it as one input among several.

**Q3:** Why might SRUM and Prefetch together be stronger than either one alone?

Prefetch says "the binary ran." SRUM says "the binary did this much network and resource work while running." Together they distinguish a binary that executed and exited (Prefetch only) from a binary that executed and pulled or pushed significant data (Prefetch plus a SRUM row with non-trivial bytes). The two are independent enough that a binary recorded in both is harder for an adversary to clean up than one recorded in either alone.

**Sample behavior-patterns table (six entries):**

| Behavior Pattern | Artifact(s) to Use | Why It Matters |
|---|---|---|
| Suspicious process with network usage | SRUM Network Data, EDR network events | Confirms the binary did real network work, not just appeared in process listing |
| GUI launch of suspicious program | UserAssist | Confirms user interaction with the binary |
| Unexpected resource usage by an application | SRUM Application Resource Usage | High CPU / disk for a low-profile binary is a quiet anomaly |
| Background process with no GUI launch | Prefetch + SRUM, no UserAssist row | Suggests launch via service, scheduled task, or parent process |
| Brief one-off binary that did real work | Prefetch RunCount=1 + SRUM bytes | The single-run binary that actually pushed data is exactly the exfil pattern |
| Burst of network activity from a low-traffic app | SRUM hourly bins | Catches beacon-style bursts that average out over a day |

---

## Task 5 — Review Shellbags and Folder Navigation Evidence

**Sample table:**

| Artifact | What It Can Reveal | Why It Matters | Limitation |
|---|---|---|---|
| Shellbags | Folders the user navigated through Explorer, including local, removable, network, and ZIP paths, with FirstInteracted / LastInteracted | Survives deletion of the folder and removal of the volume. It lives in the user's `UsrClass.dat`, so it does not survive deletion or re-creation of that profile | Records navigation, not file open or copy; depth limit; "view-only" cases still create entries |
| Explorer-related history (TypedPaths, RecentDocs MRU) | Paths the user typed or recent documents per extension | Distinguishes "knew where to go" (typed) from "clicked through tree" | Short MRU lengths; rolls off |
| Typed paths | Up to 25 most recent address-bar entries | Strong "the user already knew the path" signal | No timestamps; only the most recent N entries |

**Q1:** Why are Shellbags useful even when the underlying folder no longer exists?

Shellbags are stored in the user's `UsrClass.dat` registry hive, independent of the file system on the volume they reference. When a USB is unplugged or a network share is dismounted, the shellbag entries persist. The FIN-WS23 dataset shows `F:\Vendors\Confidential\` shellbag entries that remain readable after the SanDisk USB was disconnected. That is normal behavior, and it makes shellbags one of the most durable artifacts on Windows.

**Q2:** Why can folder-browsing evidence matter in a removable-media case?

Shellbag entries that pair a USB drive letter with sensitive folder names, such as Confidential, Salary, or Personnel, are the central evidence that someone *used* the USB rather than just plugged it in. Their FirstInteracted and LastInteracted values also fix when the navigation happened, which lets you build the device-engagement window. Without shellbags, removable-media cases stall at "the device was connected."

**Q3:** Why is browsing a folder different from proving a file was copied?

A shellbag tells you that the user, or someone using the user's account, opened the folder in Explorer. It does not show file selection, file open, or file copy. To go from browse to copy, you need more artifacts. LNK files with a matching volume serial show a file open. USN Journal entries with `FileCreate` / `DataExtend` on the USB volume show a copy. Prefetch for `xcopy.exe` / `robocopy.exe` whose referenced-file lists include paths on that drive letter can also support the copy step. Prefetch does not record command lines. Each step in browse → open → copy is a separate evidentiary claim.

**Sample folder-type table:**

| Folder or Path Type | Why It Is Relevant |
|---|---|
| USB volume path | Removable-media engagement |
| OneDrive or sync-root path | Cloud staging area |
| Downloads | Where delivered files land |
| Desktop | Common staging location and where users often place sensitive files |

**Six added entries (sample):**

| Folder or Path Type | Why It Is Relevant |
|---|---|
| `%LocalAppData%\Temp\` | Where many droppers stage payloads |
| `\\fileserver\<share>\` | Network share access — important for lateral or insider cases |
| `C:\Users\Public\` | Cross-user staging area |
| `C:\ProgramData\<vendor>\` | Sometimes used for fileless persistence drop |
| `C:\Windows\Temp\` | Service-context staging |
| Compressed archive paths (`*.zip\`) | Indicates the user opened a ZIP in Explorer — possibly an archived payload |

---

## Task 6 — Profile Removable Device Involvement

**Sample table:**

| Question | Best Artifact(s) | What Would Strengthen the Theory |
|---|---|---|
| Was a USB storage device connected? | USBSTOR, MountedDevices, Setupapi log | Single-use device with `FirstConnected == LastConnected` and an unfamiliar serial |
| Was the device browsed in Explorer? | Shellbags with the assigned drive letter | Folder names indicating sensitive content browsed during a short window |
| Were files likely opened from the device? | LNK files whose `VolumeSerialNumber` matches the USB's volume | Multiple LNKs covering distinct files on that volume, with `MountedDevices` tying the volume to the device |
| Were suspicious files staged near the same time? | RecentDocs, OpenSavePidlMRU, Office MRU | Sensitive-file names in MRUs co-occurring with USB navigation |
| Is there evidence consistent with file movement involving removable media? | USN Journal $J entries on the USB volume; Prefetch for copy utilities | `FileCreate` and `DataExtend` USN entries on the USB drive letter or a Prefetch entry for `xcopy.exe` / `robocopy.exe` with command-line references |

**Q1:** Why is device connection only the starting point in a removable-media investigation?

Connection proves only that a piece of hardware was attached. It says nothing about whether anyone interacted with it, whether the volume was mounted long enough for meaningful activity, or whether the activity was malicious. Most users plug in devices constantly, such as phones, keyboards, headsets, and backup drives. The investigation's work is to distinguish those from the device that mattered. Device connection is question one of about eight.

**Q2:** Why is correlation between device artifacts and file-access artifacts so important?

Each artifact narrows the claim and reduces the ways the evidence can be explained away. USBSTOR shows "a USB existed." Shellbags show "someone navigated folders on it." LNK files show "specific files were opened from it." In court, "the device was attached" alone is weak. This chain is hard to contest: "the device was attached, mounted as `F:`, the user browsed `F:\Vendors\Confidential\`, and two specific files were opened from a volume with this exact serial number."

**Q3:** What additional evidence would you want before briefing leadership that removable media was likely involved?

Start with evidence of writes to the USB during the device-engagement window. USN Journal entries can show file creates or writes on the USB drive letter. Prefetch entries for copy utilities (`xcopy`, `robocopy`, `7z`) whose referenced-file lists include USB paths add support, as do EDR FileCreate events on the removable volume. Optionally, recover the device physically for content review. Also hold a clean Q&A with the user about whether the device was theirs. Many "exfiltration via USB" cases turn out to be user backup or personal-device use.

---

## Task 7 — Correlate Browser, Email, and Search Artifacts

**Sample table:**

| Artifact Source | What It May Reveal | Why It Matters |
|---|---|---|
| Browser history | URLs visited, timestamps, transition types | Anchors delivery and external-access timeline |
| Browser downloads | Downloaded files, source URL, target path | Direct chain from URL to a file on disk |
| Email artifacts or mail client clues | OST/PST, Outlook MRU, attachment cache | Phishing context, attachment names |
| Search index or related search evidence | Windows Search index entries for documents and email content | Often the only fast way to find user-typed content |
| RecentDocs / LNK correlation | Recently opened documents tied to applications and devices | Connects browser/email delivery to actual file-open |

**Five added entries (sample):**

| Artifact Source | What It May Reveal | Why It Matters |
|---|---|---|
| Browser cache | Cached copies of pages, scripts, images | Sometimes preserves the delivery page when the live URL is gone |
| Edge/Chrome SiteCache / IndexedDB | Per-site state — sometimes preserves SaaS account context | Useful when the delivery channel is a SaaS file-share |
| Outlook attachment cache (`%LocalAppData%\Microsoft\Outlook\Content.Outlook\<id>\`) | Files extracted from email attachments | The attachment itself, even if the email is gone |
| MAPI / Outlook MRU | Recently composed-to or accessed addresses | Phishing-correspondent identification |
| Office Identity / DocRecovery | Auto-recovered Office files | Sometimes recovers attached document content |

**Q1:** Why can browser and email artifacts be critical in determining initial access?

Most opportunistic intrusions start with a click on a phishing email, a malvertising URL, or a SaaS-shared file. Browser history with the suspicious URL and transition type, plus the matching downloads entry, anchors initial access. In the FIN-WS23 walkthrough, the `finance-news-daily.example.com` visits in browser history give you the delivery domain. Without them, the case starts at "a Word doc opened from somewhere" and stays there.

**Q2:** Why is download evidence helpful when paired with Prefetch or Jump Lists?

Browser downloads give you the URL, the downloaded filename, and the on-disk target path with a timestamp. Prefetch for that filename closes the loop on execution. A Jump List for Word with the document name closes the loop on the user opening it. The three-way chain of URL → file → execution or open is much stronger than any single artifact, and it is the standard delivery-chain reconstruction.

**Q3:** Why should responders be cautious about assuming the user knowingly caused the event?

The artifacts show what the user's session did, not what the user was thinking. Users click things every day. Many phishing campaigns are convincing enough that no observer would expect a typical user to spot them, and drive-by attacks require no conscious user action. Frame the user's role as "the click happened in this user's session," not "the user intentionally caused this." Change that framing only when an interview, policy violations, or context push you toward attribution, such as a personal-OneDrive sync of HR docs after hours.

---

## Task 8 — Build a Behavioral Timeline

**Sample 12-row timeline (using the FIN-WS23 dataset):**

| Time (UTC) | Artifact Source | Event or Observation | File / Path / Device | Why It Matters |
|---|---|---|---|---|
| 2024-11-13 06:31:42 | Browser history | User visited a `finance-news-daily.example.com` article, then its download URL at 06:32:18 | `download?file=Q4_Vendor_Review.docm` | Delivery vector |
| 2024-11-13 06:57:48 | Jump List (Word AppId) | Entry created for the document | `C:\Users\j.smith\Downloads\Q4_Vendor_Review.docm` | Word opened the delivered file |
| 2024-11-13 06:58:00–06:59:14 | Security EID 4688 | `WINWORD.EXE` starts, spawns `powershell.exe` at 06:58:30, which launches `dl.exe` at 06:59:14 | Process chain | Macro-to-loader chain, recorded directly |
| 2024-11-13 06:59:14 | Prefetch | `DL.EXE` ran once | `C:\Users\j.smith\Downloads\dl.exe` | New-on-host loader |
| 2024-11-13 06:59 (close) | Amcache | SHA-1 captured for `dl.exe` | `b8e3f4d12a89c4e56701...` | Threat-intel pivot |
| 2024-11-13 07:00 bucket | SRUM | `dl.exe` sent 1,428,421 bytes and received 4,842,184; `powershell.exe` received 2,415,891 | Per-process network rows | Loader and its parent used the network |
| 2024-11-13 09:14:08 | USBSTOR | SanDisk Cruzer Glide first-connected | Serial `4C530001190405104544` | Device introduced about two hours later, the same morning |
| 2024-11-13 09:14:12 | System EID 98 | Volume `{b4d722a1-1142-11ef-8a4f-0c9d92841421}` reported healthy as `F:` | `usbstor.csv` assigns this GUID to serial `4C530001190405104544` | Binds `F:` to the SanDisk. No `MountedDevices` export exists, so the chain is partial |
| 2024-11-13 09:14:55–09:16:42 | Shellbags | Navigation `F:\Personal\`, `F:\Vendors\` (09:15:32), `F:\Vendors\Confidential\` (09:16:42) | Drive `F:` | User browsed sensitive folder tree on USB |
| 2024-11-13 09:16:18 and 09:16:42 | LNK files | Two LNKs with `VolumeSerialNumber=B4D7-22A1`: `Vendor_Confidential_Roster.xlsx` and `Bank_Account_Notes.docx` | `F:\Vendors\Confidential\` | Specific files were opened from the USB volume |
| 2024-11-13 09:16:18 | UserAssist | `EXCEL.EXE` last executed through the GUI | `LastExecuted` matches the roster LNK | The user opened the spreadsheet interactively |
| 2024-11-13 09:24:47 | USBSTOR | Device removed (`LastRemovalTime`) | Serial `4C530001190405104544` | Closes a 10-minute device-engagement window |

The dataset has no USN Journal, so it cannot show whether anything was copied *to* the USB. List the `F:` volume's USN Journal as a next step, not a finding.

**Q1:** Which entries appear most central to the case theory?

Two sets of entries carry the case. The Prefetch + Amcache pair for `DL.EXE` shows a one-time loader execution with the SHA-1 captured. The LNK files on volume `B4D7-22A1` show specific files opened from `F:`, and EID 98 with USBSTOR ties `F:` to the SanDisk. The browser-history delivery URL and the Word Jump List entry establish the delivery chain that produced the loader. The shellbags establish device-engagement context for the USB half of the case.

**Q2:** Which entries may be supportive but not central?

UserAssist GUI-launch entries are useful corroboration but do not by themselves move the case. SRUM is supporting context unless the byte counts are dramatically unusual. The USBSTOR row alone is mostly inventory — its weight comes from being tied to a single-day connection profile and, through EID 98, to the `F:` volume the LNK files point to.

**Q3:** What gaps remain after this timeline?

Three gaps remain. SRUM shows that `dl.exe` used the network, but network flow or EDR network events would show *where* it connected, because SRUM records no destination. USN Journal entries on the `F:` volume, or Prefetch for copy utilities whose referenced-file lists include `F:` paths, would show whether files were copied to or from the SanDisk USB. Proxy and DNS pivots would show whether the same delivery URL hit other users on the network.

---

## Task 9 — Separate Strong Support from Overclaims

| Statement | Classification | Why |
|---|---|---|
| A suspicious executable likely executed on the host | Strongly supported | Prefetch + Amcache convergent on the same binary, recent and one-shot run |
| The user opened a document from a removable device | Suggested but needs corroboration | LNK with matching volume serial is suggestive; want a Word Jump List entry whose path is on the USB drive letter to make it strong |
| The removable device was used to copy sensitive files off the system | Suggested but needs corroboration | Connection + browsing + LNK are not the same as copy; needs USN Journal / Prefetch for copy utility |
| A folder associated with a USB device was browsed in Explorer | Strongly supported | Shellbag entries are direct evidence of folder navigation |
| A program showed network-usage patterns worth further review | Strongly supported (as a lead) | SRUM bytes for a low-profile binary is itself the finding; what it means is a separate question |
| The user intentionally exfiltrated data | Not supported by these artifacts alone | Intent never proven by host artifacts; needs interview, policy context, prior behavior |
| A specific application likely opened a particular document | Strongly supported | Jump List indexed by AppId is precise about which application opened the file |
| A suspicious archive in Downloads was part of the incident chain | Suggested but needs corroboration | The archive's presence in Downloads is suggestive; need Prefetch / Amcache for an extractor and execution evidence for what came out of it |

**Six added statements (sample):**

| Statement | Classification | Why |
|---|---|---|
| `DL.EXE` ran exactly once on 2024-11-13 06:59:14 | Strongly supported | Prefetch `RunCount=1` and `LastRun` are direct evidence |
| The SanDisk USB serial `4C530001190405104544` was mounted as `F:` | Strongly supported | USBSTOR gives the device's volume GUID, and System EID 98 at 09:14:12 maps that GUID to `F:`. No `MountedDevices` export is present |
| The Word document had a malicious macro | Suggested but needs corroboration | Word Jump List shows it was opened; need oledump or VBA review to confirm malicious content |
| `DL.EXE` was downloaded from `finance-news-daily.example.com` | Suggested but needs corroboration | Browser history shows visits to the domain; need browser-downloads entry tying the URL to the file |
| The user knew the document was malicious | Not supported by these artifacts alone | Intent / awareness is not in any host artifact |
| The two LNK files prove files left the host on the USB | Not supported by these artifacts alone | LNK proves files were *opened* from the USB, not that files were *written to* the USB |

---

## Task 10 — Shell and Application Artifact Summary

**Sample summary:**

Shell and application artifact review of FIN-WS23 shows a delivery → loader → device-engagement chain on the morning of 2024-11-13. At 06:31:42 and 06:32:18, browser history shows a `finance-news-daily.example.com` article and then the download URL for `Q4_Vendor_Review.docm`. At 06:57:48, the Word Automatic Jump List records the macro-enabled document. Security EID 4688 then records `WINWORD.EXE` spawning `powershell.exe` at 06:58:30, which launched `C:\Users\j.smith\Downloads\dl.exe` at 06:59:14. Prefetch confirms that one execution (`RunCount=1`), and Amcache captures the binary's SHA-1. Four sources describe one Word → PowerShell → loader chain.

Later the same morning, USBSTOR records a SanDisk Cruzer Glide (serial `4C530001190405104544`) first-connected at 09:14:08 UTC. System EID 98 at 09:14:12 records volume `{b4d722a1-1142-11ef-8a4f-0c9d92841421}` as drive `F:`, and USBSTOR assigns that volume GUID to the SanDisk. Shellbags over the next two and a half minutes record navigation into `F:\Personal\`, `F:\Vendors\`, and `F:\Vendors\Confidential\`, and USBSTOR records the device's removal at 09:24:47, about 10 minutes after it was attached. Two LNK files with `VolumeSerialNumber=B4D7-22A1` record files opened from `F:` at 09:16:18 and 09:16:42. The volume serial places them on `F:`, and the EID 98 / USBSTOR chain ties `F:` to the SanDisk. The volume serial alone does not name the device, and no `MountedDevices` export is present to complete the chain.

Four findings are strongly supported. `DL.EXE` executed once on 2024-11-13 06:59:14 UTC from `j.smith`'s Downloads folder, launched by a PowerShell process that Word had spawned 44 seconds earlier. The SanDisk USB with the specified serial was connected once and mounted as `F:`, and two files were opened from that USB.

Two questions still require corroboration. SRUM shows `DL.EXE` sending and receiving data, but only network flow or EDR network events would show whether it reached a C2 server. USN Journal entries on the USB volume, or Prefetch entries for copy utilities, would show whether files were copied *to* the USB rather than only opened *from* it. Recommended next steps are network flow or EDR connection data for `dl.exe` from 06:59 UTC, and the USN Journal for the `F:` volume during 09:14–09:25 UTC.

---

## Task 11 — Analyst Handoff Note

**Sample handoff note:**

```
Case Reference:    IR-2024-1113-FINWS23
Author:            (your name)
Date/Time (UTC):   2024-11-13 11:00

Most Important Shell / Application Findings:
- Prefetch + Amcache: DL.EXE ran once at 2024-11-13 06:59:14 from
  C:\Users\j.smith\Downloads\, SHA-1 starting b8e3f4d12a89c4e56701...
- Word Jump List: Q4_Vendor_Review.docm opened immediately before DL.EXE ran
- Browser history: two visits to finance-news-daily.example.com on 2024-11-13, at 06:31:42 and 06:32:18

Most Important Removable-Device Findings:
- SanDisk Cruzer Glide serial 4C530001190405104544 connected once on
  2024-11-13 09:14:08, mounted as F:
- Shellbags show navigation into F:\Vendors\Confidential\
- Two LNK files (volume serial B4D7-22A1) record file-opens on F:
- System EID 98 + USBSTOR VolumeGuid tie F: to this USB (no MountedDevices export)

What Is Strongly Supported:
- One-time execution of DL.EXE on 2024-11-13 06:59:14
- Word opening of the macro-enabled doc immediately before the loader ran
- Specific USB device connected and used for file-opens

What Is Suggested but Not Confirmed:
- Word macro spawned DL.EXE via PowerShell: recorded in Security EID 4688 (WINWORD.EXE → powershell.exe 06:58:30 → dl.exe 06:59:14); EDR ProcessCreate would add command-line and module detail
- finance-news-daily.example.com is malicious (need threat intel)
- Files were copied to or from the USB (need USN Journal)

Recommended Next Artifacts:
1. EDR process-tree for 06:58–07:05 UTC on 2024-11-13
2. SRUM Network Data Usage for dl.exe
3. USN Journal for the F: volume during 09:14–09:45 UTC

Open Questions:
- Did DL.EXE establish a C2 connection?
- Was the USB the user's own device or external?
- Were other users delivered the same URL?

Notes for Incoming Analyst:
The Word → loader chain is well-supported; the USB-engagement is separately
well-supported. The two halves are correlated only by user and same-week
timeframe — do not conflate them without more evidence. EDR for the loader
window is the highest-value follow-up.
```

---

## Task 12 — Reflection

**1. Why these artifacts matter**

Shell and application artifacts tell you what a user or process *did*: which file was opened, which application opened it, which folders were navigated, and which binaries ran. Logs tell you what services said happened, and file listings tell you what is on disk now. Most incident questions need the behavioral view. Logs answer "did the user authenticate." LNK files, Jump Lists, Prefetch, and Shellbags answer "what did they do with the session."

**2. User interaction versus execution**

A file's presence on disk is the weakest claim. An open by a specific application is stronger, and execution is stronger still. Different evidence sources support each level. Keeping the three separate prevents a common reporting failure, where "the binary was on disk" escalates into "the user ran the malware" through loose paraphrase between briefings. Always say what level of claim each artifact supports.

**3. Removable-device caution**

USB cases are emotionally compelling and frequently wrong. A device shows up, a sensitive file shows up nearby in time, and the case starts writing itself in your head before the evidence is in. Walk the chain and report what is supported at each step: connection, drive-letter binding, folder navigation, file open with a matching volume serial, and file copy with USN or Prefetch evidence. Most early "USB exfiltration" hypotheses turn out to be the user's personal backup drive or a documented work device.

**4. Correlation is the real value**

Every individual artifact has a known weakness, and correlation offsets those weaknesses. Prefetch can be deleted or absent. Jump Lists can roll off. UserAssist can miss command-line execution. LNK files can be created by non-open events. Shellbags can reflect view-only access. Pair any two of them on the same event, and the case becomes harder to dispute. Pair four or five, and an adversary would need unusual effort to undermine the conclusion. Cross-artifact correlation is what produces defensible IR reports rather than artifact-tour summaries.

---

## Ready-to-move-on self-check

Before starting Lab 07, confirm you can answer these three questions cold. If any feel wobbly, revisit the relevant task.

1. **Which artifact ties a recently-opened file to the specific application that opened it?**  *Answer:* Automatic Jump Lists — they are indexed by ApplicationID, so a `Q4_Vendor_Review.docm` entry in the Microsoft Word jump list directly attributes the open to Word.
2. **What does it mean when a Prefetch entry has `RunCount=1` and a `LastRun` within the last 24 hours?**  *Answer:* The binary ran exactly once on this host very recently — the textbook "new on this host" signal. It's a strong indicator for a single-purpose loader or test execution and is one of the first patterns to triage for in incidents.
3. **How do you bind a LNK file to a specific physical USB device?**  *Answer:* Through the volume, not by matching serials. The LNK's `VolumeSerialNumber` identifies the file system the target sat on. It is assigned at format time and is unrelated to the USBSTOR device serial. Match the LNK to the volume, then use `MountedDevices` to map that volume GUID to the USBSTOR device (Chapter 6 §6.5.1). FIN-WS23 has no `MountedDevices` export, so System EID 98 stands in: it maps `{b4d722a1-1142-11ef-8a4f-0c9d92841421}` to `F:`, and `usbstor.csv` assigns that GUID to the SanDisk.

---

## Walkthrough ↔ workbook bridges

> After Walkthrough Step 1, revisit Task 3.Q1 (Prefetch for execution). Your prose-only answer should now read more concretely — `DL.EXE` with `RunCount=1` and `LastRun=2024-11-13 06:59:14` is the textbook single-run-new-on-host Prefetch pattern.

> After Walkthrough Step 2, revisit Task 3.Q2 (Amcache when Prefetch is incomplete). The Amcache row showing `C:\Users\j.smith\Downloads\dl.exe` with SHA-1 `b8e3f4d12a89c4e56701...` is the threat-intel-pivotable piece your workbook answer was describing abstractly.

> After Walkthrough Step 3, revisit Task 2.Q2 (Jump Lists tying file to application). The Microsoft Word Jump List entry for `Q4_Vendor_Review.docm` is the concrete file-to-app binding — Word opened that document, not just "the document was on disk."

> After Walkthrough Step 5, revisit Task 6.Q2 (correlation across device + file-open artifacts). The two LNK files with `VolumeSerialNumber=B4D7-22A1` place specific file opens on `F:`. System EID 98 maps the SanDisk's volume GUID to `F:`, which ties those opens back to the USBSTOR record. That is what "correlation across artifact classes" looks like with concrete fields.

> After Walkthrough Steps 6–7, revisit Task 7.Q1 (browser/email for initial access). The `finance-news-daily.example.com` visits in browser history plus the macro-enabled Word document opened 25 minutes later is the delivery → loader chain your workbook answer was describing.
