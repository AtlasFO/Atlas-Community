# Getting `xmount` working alongside GIFT-PPA Plaso

`install.sh` skips `xmount` with a warning whenever Plaso came from the
GIFT PPA (`ppa:gift/stable`) — which is the default on Ubuntu 24.04/22.04.
This page explains why, and gives two ways to close the gap: one that
needs no extra work (you probably already have it), and one that restores
real `xmount` in a few minutes.

## Why it fails

Ubuntu archive's `xmount` package depends on Ubuntu archive's `libewf2`.
GIFT's Plaso (`python3-plaso`/`python3-dfvfs`) hard-depends on GIFT's own,
differently-packaged `libewf` build — same library, incompatible package,
and the two `Conflicts:` with each other:

```
$ sudo apt-get install -y xmount
...
The following packages have unmet dependencies:
 libewf : Conflicts: libewf2 but 20140814-1build3 is to be installed
```

You can have GIFT's Plaso *or* Ubuntu archive's `xmount` installed via
apt, never both. GIFT doesn't publish its own `xmount` build, so there's
no drop-in package to reach for.

## Option 1 — you probably don't need it

`xmount`'s job in Atlas is mounting a disk image (E01/AFF/raw) as a raw
device, or converting between image formats. Atlas already covers both
without `xmount`:

**E01 → raw / NTFS mount** — `ewfmount` (installed from GIFT alongside
Plaso, as `libewf-tools`) does this directly:
```
sudo ewfmount case.E01 /mnt/ewf
# /mnt/ewf/ewf1 is now a raw device-like file
```
Atlas's own `ewf.mount_full_image` / `ewf.ewf_mount` tools already do
exactly this — no `xmount` step involved.

**Format conversion (E01/VMDK → raw)** — `qemu-img` (installed by
`install.sh` as part of `qemu-utils`) handles this, and is what Atlas's
`img.vmdk_export_raw` already uses:
```
qemu-img convert -O raw case.vmdk case.raw
```

Between `ewfmount` and `qemu-img`, this covers every documented Atlas
workflow. If that's all you needed `xmount` for, there's nothing left to
fix.

## Option 2 — build real `xmount` from source

If you specifically want live cross-format FUSE mounting (`xmount`'s own
niche — e.g. exposing an E01 as a virtual VDI/VHD/VMDK on the fly), it
builds cleanly against GIFT's `libewf-dev`, including a real E01 mount
and read, on Ubuntu 24.04 with GIFT's PPA already active (the same state
`install.sh` leaves your system in):

```
sudo apt-get build-dep -y xmount   # everything the package declares it needs — see below
apt-get source xmount              # unpacks xmount-<version>/ into the current directory
cd xmount-*/ && mkdir build && cd build
cmake ..
make -j"$(nproc)"
sudo make install
xmount --info                      # lists the input libraries; ewf must be among them
```

`build-dep` installs what the package's own build recipe declares: `cmake`,
`pkg-config`, `libfuse-dev`, `libafflib-dev`, `libbfio-dev`,
`libgnutls28-dev`, `zlib1g-dev` and `debhelper`. `libewf-dev` is already
satisfied by GIFT's build (a newer version than the archive's), so nothing is
downgraded or replaced. Without `build-dep`, the same by hand:
```
sudo apt-get install -y build-essential cmake pkg-config libfuse-dev \
  libafflib-dev libbfio-dev libgnutls28-dev zlib1g-dev
```
`libfuse-dev` (the FUSE 2 headers) is not optional: `cmake` stops at
"LibFUSE not found" without it, and the `fuse`/`fuse3` runtime packages
`install.sh` leaves behind do not provide it.

Both `build-dep` and `apt-get source` need the archive's source index. If
either fails with "You must put some 'deb-src' URIs in your sources", enable
it once. Ubuntu 24.04 declares the archive in a deb822 file:
```
sudo sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
sudo apt-get update
```
Ubuntu 22.04 and older use the one-line format instead:
```
echo "deb-src http://archive.ubuntu.com/ubuntu $(lsb_release -cs) main universe" \
  | sudo tee /etc/apt/sources.list.d/archive-src.list
sudo apt-get update
```

This works because GIFT's `libewf-dev` ships the same header/pkg-config
surface (`libewf.h`, `libewf.pc`) as Ubuntu archive's — `cmake` finds it
via pkg-config the same way either way, despite the two runtime packages
being named differently (`libewf` vs `libewf2`). No source patching
needed.

`xmount` installed this way is **not tracked by `install.sh`'s manifest**
(`uninstall.sh` won't remove it) — it's a manual, out-of-band addition on
your part. To remove it later: `cd xmount-*/build && sudo make uninstall`
(or just `sudo rm` the installed binary/plugins if that target doesn't
exist in your build).
