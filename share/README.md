# Shared reference data

Install-time assets that are not investigation cases.

| Path | Purpose |
|------|---------|
| `.common/mitre_*.json` | ATT&CK tables (techniques, groups, software, mitigations) copied into `~/cases/.common/` by `install.sh` — refreshed whenever the repo's copy differs; rebuilt with `python -m tools.mitre.build_mitre_cache`, or for one machine from Settings → MITRE ATT&CK |
| `atlas-sudoers.in` | Least-privilege sudoers template → `/etc/sudoers.d/atlas-$USER` |
| `atlas-sudoers.bins` | Basename inventory for the sudoers grant (kept in sync by tests) |
| `atlas-dashboard.service.in` | systemd unit template → `/etc/systemd/system/atlas-dashboard.service` |
| `scalpel.conf` | The configuration `carve.scalpel_carve` and `jobs.job_start_scalpel_carve` use unless told otherwise: scalpel's upstream file with the families foremost carves by default uncommented (the file scalpel installs enables nothing and is refused). Enable more types the way its comments describe; read in place by `tools/carving.SCALPEL_CONF`, not copied anywhere |

When adding a new `needs_sudo=True` wrapper, update **both** `atlas-sudoers.bins` and `atlas-sudoers.in`, then run `bin/atlas-sudoers` (or `./install.sh`).

`atlas run` / `train` refuse to start until `bin/atlas-sudoers --check` passes.
