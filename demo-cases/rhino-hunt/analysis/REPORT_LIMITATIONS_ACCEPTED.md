# Report Limitations Accepted

## Indicators accepted without a finding

- **ab578fdabe4963a212c2e6695bb25248** (seen in 4 calls): This is NOT a file hash. It is the Hotmail session token — the value of the `a=` CGI parameter in Hotmail webmail URLs (e.g. `GET /cgi-bin/HoTMaiL?curmbox=F000000001&a=ab578fdabe4963a212c2e6695bb25248&fti=yes`). It appears in 39 hits across the Hotmail session in rhino.log as the session identifier for the hugerhinolover@hotmail.com webmail session. It is a web application session token, not a cryptographic hash of any file. Dispositioned in call 337.

## Task limitations

- **task-0003 p1** (prove the connection between USB content and network traffic, relation): The connection is established by the 'gnome' account appearing in both the carved diary on the USB key (USB-side) and the FTP/HTTP/telnet sessions in the pcaps (network-side). No hash, filename, or byte-level match directly links a specific USB artifact to a specific network transfer — the connection is by shared account identity and timing, not by file content. This is the strongest relation the evidence supports. C0017 states this relation.

## Stego extraction limitation

- The two carrier images holding JPHide steganographic payloads are among the 7 carved rhino JPGs on the reformatted USB key. The JPHide passwords are derivable from the recovered diary and decoy files (monkey, gator, gumbo). The steg_extract tool (jpseek 0.3) was run over the carved JPGs with all three passphrases but returned no extractable payload: the carriers use JPHide 0.5x (Windows) format, which jpseek 0.3 cannot read. The specific filenames of the two carrier images cannot be determined without a JPHS-compatible extraction tool.