# Network share (SMB) — copy evidence in without SSH

By default, evidence has to land on the Atlas host's local disk — usually
by copying it over SSH — before a case can be worked. The network share
feature exposes your cases folder over SMB instead, so a Windows machine
can mount it directly, drop evidence into a case folder, and edit
`CASE.md`, without a login on the Atlas host at all.

**Scope**: single-user/single-host only. The share always authenticates as
*your* own account and exposes *your* `ATLAS_CASES_ROOT` (default
`~/cases`). It does not extend to the multi-user shared-VM model described
in [multi-user.md](multi-user.md) — each analyst there still works over
SSH for now.

## What you get

Mount `\\<this host>\atlas-cases` from Windows and you'll see your case
folders directly — not a wrapping "cases" folder. Open one, copy evidence
in, edit `CASE.md`, same as if you'd done it locally.

## Enabling it

Three equivalent ways — pick whichever fits how you work:

- **During install**: `install.sh` asks "Set up an SMB network share...?"
  (default: no). Answer yes, or pass `--with-network-share` /
  `ATLAS_INSTALL_NETWORK_SHARE=1` for unattended installs.
- **Dashboard**: Settings → **Network share** → Turn on, then set a
  password.
- **CLI**: `bin/atlas share enable`, then `bin/atlas share passwd`.

All three call the same underlying code (`core/smb_share.py`), so status
shown in one place matches the others.

`bin/atlas share status` (or the same section, through the same GET route) shows whether samba
is installed, whether the share is enabled, whether `smbd` is running, and
whether a Samba password has been set yet.

## Security model

- **Auth**: the share authenticates as your existing Linux **username**,
  but with a **separate Samba-only password** — Samba keeps its own
  password database (`tdbsam`), entirely decoupled from your Linux login.
  A leaked Samba password grants share access only, never SSH/sudo/login.
- **Encryption required, SMB2+ only**: `smb encrypt = required` and
  `server min protocol = SMB2` are set unconditionally — SMB1
  (EternalBlue-class vulnerable) is refused, and evidence never crosses
  the LAN in cleartext.
- **No guest access**: every connection must authenticate as your user;
  `guest ok = no` / `map to guest = never`.
- **The dashboard is never sudo-capable for this.** Every privileged step
  (writing `/etc/samba/atlas-share.conf`, `smbpasswd`, restarting `smbd`)
  goes through a single fixed-command wrapper, `bin/atlas-smb-share`,
  invoked via `sudo -n` under a narrowly-scoped, literal sudoers grant
  (`share/atlas-sudoers.in`) — not general sudo access for the dashboard
  or CLI process.
- **Your host's existing Samba config, if any, is left alone.** The share
  lives in its own include file (`/etc/samba/atlas-share.conf`), added via
  one appended `include =` line in `/etc/samba/smb.conf` — nothing else in
  that file is parsed or rewritten.

## Firewall — your responsibility, not automatic

Enabling the share does **not** open any firewall ports. `install.sh` has
no `ufw`/`iptables` management at all, and auto-opening 139/445 would be a
host-level change this feature deliberately doesn't make for you. If a
firewall is active, allow SMB (139/445) from your LAN yourself — e.g. on
Ubuntu:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 139,445 proto tcp
```

Scope this to your actual LAN range — never expose SMB to the open
internet.

## Disabling it

- Dashboard: Settings → **Network share** → Turn off.
- CLI: `bin/atlas share disable`.

This removes the share config and the `smb.conf` include line, but leaves
the `samba` package installed (in case you use Samba for anything else on
this host) and never stops/disables `smbd` itself. To also remove the
package: `./uninstall.sh --purge-system-packages` (only removes it if
Atlas itself installed it — see `.install-manifest.json`).

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Settings page / CLI says "samba not installed" | Run `install.sh` with the network-share option, or `sudo apt-get install samba` then `bin/atlas-sudoers && bin/atlas share enable`. |
| "sudo: a password is required" in status/enable | The `ATLAS_SMB_SHARE` sudoers grant isn't installed yet — run `bin/atlas-sudoers` (installs from `share/atlas-sudoers.in`), then retry. |
| Windows can't connect | Check the firewall (see above), and that `smbd` is running (`bin/atlas share status`). |
| Windows connects but asks for credentials repeatedly | Password not set yet — `bin/atlas share passwd` or the dashboard's password field. |
| Enabled the share, but changed `ATLAS_CASES_ROOT` afterward | Re-run `bin/atlas-sudoers` (it re-templates the sudoers grant to the new cases root) and `bin/atlas share enable` again. |
| "System has not been booted with systemd as init system... Failed to connect to bus" | Normal in containers (distrobox, Docker) that don't run systemd as PID 1 — real Ubuntu installs have systemd, containers usually don't. `bin/atlas-smb-share` detects this (`/run/systemd/system` absent) and starts/reloads `smbd` directly instead of via `systemctl`. If you still hit this, make sure `bin/atlas-smb-share` is the one this release ships. |
