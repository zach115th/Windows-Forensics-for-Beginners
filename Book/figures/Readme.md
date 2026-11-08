# Figures — Windows Forensics for Beginners

This folder holds the screenshot images referenced from the chapters in `Book/`. Each chapter that needs a figure carries a **placeholder blockquote**, which starts with `> **Figure N.M — _placeholder for`, at the spot where the image belongs; once you capture the screenshot and save it here using the filename in the placeholder, the placeholder can be swapped for an `![alt](figures/<filename>.png)` link plus an italic caption.

## The cover image

`Book/Cover.md` expects the cover at **`Book/figures/cover.png`**. Upload the file at exactly that path and the cover page renders with no further edits — nothing else needs changing.

Specs, if the image is still being produced or resized:

| Property | Target | Why |
|---|---|---|
| Filename | `cover.png` | Referenced literally by `Cover.md`; a different name means editing the page |
| Aspect ratio | 1.6 : 1 (portrait) | The EPUB/Kindle standard; 2 : 3 also renders acceptably |
| Dimensions | 1600 × 2560 px | Kindle's recommended size; anything under 1400 px wide looks soft on retail pages |
| Format | PNG (or JPEG) | PNG for text-heavy covers, JPEG if the file exceeds a few MB |
| File size | under ~5 MB | Keeps the repo light; see `CONTRIBUTING.md` on binaries |

The `Cover.md` page constrains the display width to 600 px, so a large source image is fine — it will be scaled down for GitHub rendering while staying full resolution for an ebook build.

If you also want a low-resolution copy for fast README loading, name it `cover-small.png` and leave `cover.png` as the full-size original.

## Conventions

- **Filenames**: `fig-<chapter>-<seq>-<short-description>.png`, all lowercase, hyphens not underscores. Example: `fig-4-1-timeline-explorer-mft.png`.
- **Captions** in the chapter live as a single italicized line directly under the image: `*Figure 4.1 — caption text.*`
- **Alt text** in the `![alt](path)` should be a short description of what the image shows, for accessibility and so the figure still conveys meaning when the PNG is missing or fails to load.
- **Image specs**: PNG, 1600×1000 max, lossless. Crop tightly; redact any account names, internal IPs, or hostnames that are not from the simulated `Data/` sets in this repo.

## Planned figures

| # | Figure | Filename | Where it goes | What to capture |
|---|---|---|---|---|
| 1 | Figure 4.1 | `fig-4-1-timeline-explorer-mft.png` | `Chapter04.md` §4.4 (Tools) | Timeline Explorer with `Data/WKSTN-221/mft.csv` loaded, sorted by `Created0x10` desc, the `update.exe` row in `Temp\` highlighted. |
| 2 | Figure 5.2 | `fig-5-2-registry-explorer-runkey.png` | `Chapter05.md` §5.2 (Important Keys for IR) | Registry Explorer (Eric Zimmerman) showing `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with a benign user value visible. Use a non-suspect host like the lab baseline. |
| 3 | Figure 6.2 | `fig-6-2-lecmd-lnk.png` | `Chapter06.md` §6.1.1 (LNK Files) | LECmd CLI output for a Recent LNK pointing at the `Q4_Payroll_Review.xlsm` lure document, showing target path, target IDs, and volume serial. |
| 4 | Figure 6.3 | `fig-6-3-pecmd-prefetch.png` | `Chapter06.md` §6.1.3 (Prefetch) | PECmd CSV opened in Timeline Explorer, with `update.exe`, `cmd.exe`, `powershell.exe` rows visible and run counts shown in a separate column. |
| 5 | Figure 7.1 | `fig-7-1-memprocfs-mount.png` | `Chapter07.md` §7.2 (Tooling) | MemProcFS mounted at `M:\` in File Explorer, showing the `name\` directory with the suspicious `powershell.exe-3704\` subtree expanded. |
| 6 | Figure 8.2 | `fig-8-2-wireshark-c2.png` | `Chapter08.md` §8.3 (Capture and IR-Focused Analysis) | Wireshark with display filter `ip.addr == 91.214.47.22`, showing the C2 conversations, time column visible, follow-stream context menu open. |
| 7 | Figure 9.2 | `fig-9-2-eventviewer-4625.png` | `Chapter09.md` §9.1.1 (Security) | Event Viewer with a single 4625 (failed logon) event highlighted, the *General* and *Details* tabs visible. Use the lab data so the fields are simulated. |
| 8 | Figure 9.3 | `fig-9-3-hayabusa-timeline.png` | `Chapter09.md` §9.3.2 (Tooling to Parse at Scale) | Hayabusa terminal output of `csv-timeline -d <Logs> -p super-verbose` against the WKSTN-221 logs, showing the rule-hit summary and the top-priority detections. |
| 9 | Figure 10.1 | `fig-10-1-timeline-explorer-merged.png` | `Chapter10.md` §10.3 (Common Tools) | Timeline Explorer with a merged Lab 10 CSV loaded (the same shape as `Labs/Lab10/timeline-template.csv`); the `update.exe` pivot row highlighted. |
| 10 | Figure 11.2 | `fig-11-2-iris-case-timeline.png` | `Chapter11.md` §11.6 (Writing a Case Summary) | IRIS-NG case view showing the imported timeline (events from the HR-WS17 capstone), with the pivot event annotated and color-coded. |
| 11 | Figure 12.2 | `fig-12-2-extension-sweep.png` | `Chapter12.md` §12.3 (Scoping the Encryption) | `Data/ACCT-FS01/encrypted-files-inventory.csv` grouped by directory, showing the 418-file / 73.26 GiB total and `C:\Shares\IT\Backups\SQL` at 91.8% of the volume from 5 files. |
| 12 | Figure 12.3 | `fig-12-3-usn-encryption-burst.png` | `Chapter12.md` §12.3 (Scoping the Encryption) | `Data/ACCT-FS01/usn-journal.csv` in Timeline Explorer, sorted by `UpdateTimestamp`, showing the mass-modification burst between 02:14 and 03:38. The visual density of the burst against the sparse baseline above it is the whole point of the figure. |
| 13 | Figure 12.4 | `fig-12-4-ransom-note.png` | `Chapter12.md` §12.3 (Scoping the Encryption) | A `RECOVER-YOUR-FILES.txt` note open in Notepad beside an Explorer window showing the same directory full of `.vaulted` files. Use the Lab 12 scenario text, not a real group's note — no real onion addresses or payment addresses. |
| 14 | Figure 13.1 | `fig-13-1-confidence-table.png` | `Chapter13.md` §13.2 (The Anatomy of a Defensible Finding) | A finished findings table from a real (sanitized) report showing the Confirmed / Probable / Possible / Undetermined column in use across several findings. Redact everything identifying. |
| 15 | Figure 13.2 | `fig-13-2-exec-brief.png` | `Chapter13.md` §13.3 (Report Structures That Work) | A one-page executive brief, sanitized. Readers benefit more from seeing the shape and density of a real brief than from any description of one. |
| 16 | Figure D.2 | `fig-d-2-hayabusa-cli.png` | `AppendixD.md` §D.6 (Hayabusa) | Hayabusa CLI run with `--rules` and a Sigma update, showing the rule count, the Logon-failures rule firing, and the resulting CSV path. |

## Replacing a placeholder

When you capture a figure, edit the chapter file and replace its placeholder blockquote with this two-line idiom, using the alt text from the placeholder as the alt text here:

```markdown
![Figure 4.1 — Timeline Explorer with the WKSTN-221 MFT loaded; update.exe row highlighted](figures/fig-4-1-timeline-explorer-mft.png)
*Figure 4.1 — Timeline Explorer browsing the WKSTN-221 MFT, sorted by `Created0x10`. The `update.exe` row at the highlighted line is the one to focus on for the lab walkthrough.*
```

That keeps the figure self-describing whether or not the PNG renders.

## Notes

- **Do not** screenshot Microsoft / Sysinternals / EZ Tools menus and toolbars from versions of those tools you can't redistribute. Crop to the data view itself, and confirm the tool's license allows redistribution of UI screenshots if you have any doubt.
- **All scenario data must come from `Data/`** in this repo (which is simulated). Do not include real corporate hostnames, usernames, IPs, or document names in any captured figure.
- **The mermaid diagrams** already in the chapters are not "figures" in this index — they are not screenshots, they're text-rendered, version-controlled, and don't need a PNG. Don't duplicate them here.
