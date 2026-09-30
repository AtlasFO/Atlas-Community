# Third-party software Atlas uses

Atlas drives a large set of forensic tools. Almost none of them are shipped
in this repository: `install.sh` installs them onto your machine from their
own distributors, and Atlas executes them as separate programs. Running a
program is not the same as distributing it, so those tools place no notice
obligation on this repository — the material Atlas actually redistributes,
and the notices that go with it, are in [NOTICE](NOTICE).

This file exists for a different reason: so you can see what Atlas will put
on a machine, under what terms, before you install it, and so the few items
that need a decision rather than a line of credit are written down.

Licences below were read from the installed artifacts — Python distribution
metadata in the virtualenv, and `/usr/share/doc/<pkg>/copyright` for system
packages — not from memory. Where a licence is recorded as *see upstream*,
it was not verified mechanically and you should check the project before
relying on it.

## Python packages (installed by pip into the virtualenv)

| Package | Licence | Used for |
|---|---|---|
| fastmcp | Apache-2.0 | the MCP server every tool is exposed through |
| httpx | BSD-3-Clause | HTTP client (LLM providers, enrichment) |
| python-dotenv | BSD-3-Clause | `.env` configuration |
| pyyaml | MIT | playbook, config and rule parsing |
| rich | MIT | CLI rendering |
| prompt_toolkit | BSD | `atlas chat` input |
| yara-python | Apache-2.0 | `yara.*` rule scanning |
| cryptography | Apache-2.0 OR BSD-3-Clause | `crypto.decrypt` |
| argon2-cffi | MIT | dashboard password hashing |
| volatility3 | Volatility Software License 1.0 | `vol.*` memory forensics — see *Volatility 3* below |
| flare-capa | Apache-2.0 | capability analysis, ATT&CK mapping |
| flare-floss | Apache-2.0 | obfuscated string extraction |
| oletools | BSD | Office macro triage |
| openpyxl | MIT | `table.*` xlsx access |
| py-tlsh | Apache-2.0 or BSD | fuzzy hashing |
| jsbeautifier | MIT | JavaScript deobfuscation |
| markdown | BSD-3-Clause | HTML report rendering |
| machinae | MIT | multi-source IOC lookup |
| construct | MIT | binary structures for odl.py (OneDrive sync logs) |
| pycryptodome | BSD-2-Clause and public domain | AES for odl.py (OneDrive sync logs) |
| libscca-python | LGPL-3.0-or-later | prefetch parsing — see *Points that need a decision* |
| pefile | MIT | PE triage |
| usnparser | Apache-2.0 | `$UsnJrnl` parsing |
| pyhindsight | Apache-2.0 | Chrome/Chromium profile parsing |
| pe-carver | Apache-2.0 | PE carving |
| python-evtx | Apache-2.0 | EVTX records without .NET |
| analyzeMFT | MIT | `$MFT` to CSV without .NET |

## System packages (installed with apt from your distribution)

| Package | Licence | Package | Licence |
|---|---|---|---|
| binutils (`strings`) | GPL — see package copyright | binwalk | MIT (Expat) |
| bsdextrautils (`hexdump`) | GPL-2+ | clamav | GPL-2 |
| file | BSD-2-Clause-alike | foremost | public domain |
| hashdeep | public domain | libimage-exiftool-perl | Artistic or GPL-1+ |
| libparse-win32registry-perl | Artistic or GPL-1+ | ngrep | see package copyright |
| ntfs-3g | GPL-2+ | outguess | BSD-4-Clause |
| p7zip-full | GPL-2+ | parted | see package copyright |
| pff-tools | LGPL-3+ | pst-utils | GPL-2+ |
| qemu-utils | GPL-2 — see package copyright | scalpel | GPL-2+ |
| sleuthkit | see package copyright (mixed IPL/CPL/GPL) | sqlite3 | public domain |
| ssdeep | GPL-2+ | steghide | GPL-2+ |
| tcpdump | see package copyright (BSD-3) | tcpxtract | GPL-2+ |
| testdisk | see package copyright (GPL-2+) | unzip | see package copyright |
| xxd | Vim licence | radare2 | LGPL-3 |
| libewf-tools | LGPL-3.0+ | plaso-tools | Apache-2.0 |
| libbde-tools, libvshadow-tools, libesedb-utils, libevt-utils | LGPL-3+ (libyal family) | bulk-extractor | see upstream |
| **unrar** | **freeware, not free software** — see below | | |

Optional network tooling (`install.sh --with-network-tools`): zeek, suricata.
Optional PPAs and repositories the installer may add, with your consent:
GIFT (Plaso), the Zeek OBS repository, the Microsoft package repository
(.NET runtime for the EZ Tools).

## Fetched at install time from upstream releases

| Tool | Upstream | Licence |
|---|---|---|
| Chainsaw and its $MFT rules | github.com/WithSecureLabs/chainsaw | GPL-3.0 (see upstream) |
| Hayabusa | github.com/Yamato-Security/hayabusa | AGPL-3.0 (see upstream) |
| Detect It Easy | github.com/horsicq/DIE-engine | MIT (see upstream) |
| Velociraptor | github.com/Velocidex/velociraptor | AGPL-3.0 (see upstream) |
| RegRipper 4.0 | github.com/keydet89/RegRipper4.0 | see upstream |
| Didier Stevens Suite (pdfid, pdf-parser) | github.com/DidierStevens/DidierStevensSuite | see upstream (per-tool terms) |
| INDXParse | github.com/williballenthin/INDXParse | see upstream |
| DensityScout | cert.at | see upstream (freeware) |
| EZ Tools (Eric Zimmerman) | ericzimmerman.github.io | freeware, see upstream terms |
| jphide/jpseek | github.com/h3xx/jphs | see upstream |
| odl.py (OneDrive sync logs) | github.com/ydkhatri/OneDrive | MIT |
| bulk_extractor | github.com/simsong/bulk_extractor | see upstream |
| SigmaHQ rules | github.com/SigmaHQ/sigma | Detection Rule License 1.1 |

None of these are redistributed by this repository. The installer records
what it placed on the machine in `~/.cache/atlas/install_report.json` and
`.install-manifest.json`, and `uninstall.sh` removes it again.

## Points that need a decision, not a credit

**Volatility 3 (VSL 1.0).** Atlas neither ships nor imports Volatility:
`install.sh` installs it from PyPI and Atlas runs the `vol` program. The
Volatility Software License counts *"any software designed to execute the
software and parse its results, such as a wrapper written for the
software"* as an Addition, excludes *"shell or execution menu software
designed to execute software generally"*, and asks that Additions made
available to others be published as source *"under this license"* through
a freely accessible system. The project's position: Atlas's executor and
agent run around sixty tools the same way and are the general kind; the
Volatility-specific parts are `tools/volatility.py` and the two helpers in
`core/paths.py` that locate the program and its symbol tables (`vol3_bin`,
`vol3_symbols`). Their source is published in this repository and they are
offered under the VSL 1.0 in addition to Atlas's licence. A reading under
which Atlas as a whole counts as such a wrapper would ask more; this is the
project's position, not legal advice. Full text:
https://www.volatilityfoundation.org/license/vsl-v1.0

**libscca-python (LGPL-3.0-or-later).** Imported by the prefetch fallback.
Installed by pip, not redistributed here, so nothing is owed today. If Atlas
is ever shipped as a prebuilt image, container or bundled virtualenv, the
LGPL's notice and relinking obligations apply to that artifact.

**unrar is freeware, not free software.** Its licence forbids using the
source to reimplement the RAR algorithm and restricts redistribution. Fine to
install on your own machine; not fine to ship inside a prebuilt image.

**Shipping a prebuilt image changes everything above.** Every "no obligation"
statement here rests on Atlas distributing source only and installing tools
onto the user's own machine. A VM image, container or bundled virtualenv
*does* redistribute those works, and their notice, source-offer and
copyleft obligations attach to it. That would need its own review.

## Naming and affiliation

Atlas targets the same Ubuntu base as the SANS SIFT Workstation and drives
many of the same tools; its MCP server is named `atlas-sift` for that
reason. Atlas is not affiliated with, endorsed by, or sponsored by SANS or
the SIFT Workstation project, and does not redistribute SIFT. "SIFT
Workstation" and "SANS" are the marks of their respective owners; they are
used here descriptively.

ATT&CK® is a registered trademark of The MITRE Corporation. Every other
product name above belongs to its owner and is used to say which program
Atlas runs, nothing more.
