# Media assets

Screenshots referenced from the top-level [README](../../README.md).

| File | What it is |
|------|------------|
| `dashboard-overview.png` | Overview: the case's status band, its findings across the run and the answered questions |
| `dashboard-questions.png` | Questions: an answer with the claims and evidence behind it |
| `dashboard-findings.png` | Case Findings: every belief by host and confidence |
| `dashboard-process.png` | Process: the run in time, with director rulings, reasoning gates, tool calls, failures and findings |
| `logo-light.png` | The logo for light backgrounds: `dashboard/assets/logo.png` with its white parts turned dark slate; the README shows it in GitHub's light theme |

All four show the bundled `demo-cases/rhino-hunt` run, which is what `./dashboard.sh --demo` opens.
To recapture them: dark theme, a 1440x900 viewport at device scale 2, scrollbars hidden, then
Pillow's fast-octree quantizer at 256 colours (median cut shifts the small confidence dots to
the wrong colour).

Keep individual images reasonable (PNG, ideally < ~500 KB each) so the repo stays light.
