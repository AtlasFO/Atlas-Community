# Media assets

Screenshots referenced from the top-level [README](../../README.md).

| File | What it is |
|------|------------|
| `dashboard-overview.png` | Overview: the case's status band, its findings across the run and the answered questions |
| `dashboard-questions.png` | Questions: an answer with the claims and evidence behind it |
| `dashboard-findings.png` | Case Findings: every belief by host and confidence |
| `dashboard-process.png` | Process: the run in time, with director rulings, reasoning gates, tool calls, failures and findings |
| `dashboard-walkthrough.gif` | A 34-second loop: the Overview of the finished RHINO-HUNT run, *New case* filled in, *Start run* until *Run in progress*, then the RHINO-HUNT run's Questions, Case Findings, IoCs, Response and Process tabs and its report at the executive summary. The new case is invented and its run was held at its first model call by a local stub endpoint, so the recording spent no tokens |
| `logo-light.png` | The logo for light backgrounds: `dashboard/assets/logo.png` with its white parts turned dark slate; the README shows it in GitHub's light theme |

All four show the bundled `demo-cases/rhino-hunt` run, which is what `./dashboard.sh --demo` opens.
To recapture them: dark theme, a 1440x900 viewport at device scale 2, scrollbars hidden, then
Pillow's fast-octree quantizer at 256 colours (median cut shifts the small confidence dots to
the wrong colour).

Keep individual images reasonable (PNG, ideally < ~500 KB each) so the repo stays light. The
walkthrough GIF (about 2.9 MB) is the one exception: it was recorded at 1200x750, device scale 1,
with headless Chromium, a drawn cursor and per-frame durations, and quantized the same way with no
dithering.
