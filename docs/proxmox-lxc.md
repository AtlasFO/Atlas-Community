# Running Atlas in a Proxmox LXC container — loop devices

Atlas mounts disk images (E01, dd, VMDK, ...) via the kernel's loop
device driver — `tsk.*`, `img.*`, and `carving.*` all depend on it. LXC
containers (Proxmox's included) share the **host's** kernel instead of
running their own, so this needs a small amount of host-side setup that a
Docker container or a VM wouldn't.

## Why `modprobe loop` inside the container doesn't work

There's no separate kernel inside an LXC container to load a module
into — `modprobe loop` run inside the CT either no-ops or fails, because
the `loop` module has to already be loaded **on the Proxmox host**. Same
reasoning for device nodes: `/dev/loop-control` and `/dev/loopN` aren't
created inside the container automatically — they have to be explicitly
passed through from the host.

## Fix: on the Proxmox host

**1. Load the module and make it persistent** (run on the Proxmox host,
not inside the CT):

```bash
modprobe loop
echo loop > /etc/modules-load.d/loop.conf
# Optional: raise the number of loop devices available (default is often
# only 8) if you expect to mount several images at once:
echo "options loop max_loop=64" > /etc/modprobe.d/loop.conf
```

**2. Pass the device through to the container.** Edit the container's
config, `/etc/pve/lxc/<CTID>.conf` (replace `<CTID>` with your container's
ID), and add:

```
lxc.cgroup2.devices.allow: b 7:* rwm
lxc.mount.entry: /dev/loop-control dev/loop-control none bind,optional,create=file
lxc.mount.entry: /dev/loop0 dev/loop0 none bind,optional,create=file
lxc.mount.entry: /dev/loop1 dev/loop1 none bind,optional,create=file
lxc.mount.entry: /dev/loop2 dev/loop2 none bind,optional,create=file
lxc.mount.entry: /dev/loop3 dev/loop3 none bind,optional,create=file
```

Add more `/dev/loopN` lines if you raised `max_loop` and expect to need
more than 4 concurrent mounts. `7:*` is the major device number for loop
devices — the cgroup2 rule allows the whole class, the mount entries make
the actual nodes visible inside the container.

**3. Restart the container** (a reboot *inside* the CT is not enough —
this config is only re-read on container start):

```bash
pct stop <CTID>
pct start <CTID>
```

## Privileged vs. unprivileged

Proxmox's default **unprivileged** containers add an extra layer (UID/GID
remapping) on top of the above that can make device passthrough flakier
in practice — the steps above are usually enough, but if you're still
stuck, a **privileged** container removes that remapping and is more
likely to "just work" for this. Trade-off: a privileged container has
weaker isolation from the host than unprivileged — root inside the
container is closer to root on the host. For a forensics box handling
potentially-hostile evidence images, weigh that against your own threat
model before choosing it.

## If this stays fragile: use a VM instead

Loop-device passthrough into an unprivileged LXC container is a known
rough edge in the Proxmox/homelab world generally — it can behave
differently across Proxmox/kernel updates, and tightening container
isolation is exactly the kind of change that quietly breaks it again
later. Given Atlas's core job is reliably mounting evidence images, a
**Proxmox VM** (KVM) sidesteps the whole problem — a VM has its own
kernel, so loop devices work exactly like they would on bare metal, no
host-side config needed at all. If you're setting this up for real
casework rather than just trying it out, a VM is the more robust choice;
the LXC route above is for when container density/overhead matters more
than that.

## Verify before re-running `install.sh`

Inside the container, after applying the fix and restarting it:

```bash
ls -la /dev/loop-control /dev/loop0   # both should exist
losetup -f                            # should print a free loop device path, not an error
```

If both work, re-run `./install.sh` — the loop-device check should now
report success instead of the warning.
