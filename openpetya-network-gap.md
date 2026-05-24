# OpenPetya — Network-Detection Gap Analysis

| | |
|---|---|
| **Author** | Andrew Quill |
| **Created** | 2026-05-24 |
| **Modified** | 2026-05-24 |
| **Version** | 2.0 |
| **License** | Apache-2.0 |
| **TLP** | TLP:CLEAR |
| **Reference** | https://github.com/iss4cf0ng/OpenPetya |
| **Companion** | [openpetya-delivery-http.rules](openpetya-delivery-http.rules) |

---

## TL;DR

**OpenPetya produces zero outbound network traffic at runtime.** There is no
useful Suricata/Zeek/Snort signature for the *execution* of this family.
All network coverage in this pack is limited to the **delivery phase**
(artifacts arriving on a host before execution) and is *situational* —
it depends on your sensor having visibility into HTTP bodies, which for
the typical github.com delivery path means having a TLS-intercepting
sensor or only matters in retro-hunt against archived pcap.

If you do not have TLS interception and you are not doing pcap retro-hunt,
**you have no network coverage of this family — and that is correct, not a
defect**. The host telemetry layer carries 100% of the load.

---

## What the malware does and doesn't do at runtime

Confirmed from upstream README + source review (`Grep` of the entire
project tree for `WSAStartup`, `socket`, `connect`, `WinHTTP`, `WinINet`,
`bind`, `recv`, `send`, `DNS`, `HTTPS`, `HttpSendRequest`, `Bcrypt`):

| Capability | Present in OpenPetya? |
|---|---|
| Outbound HTTP / HTTPS client (C2, beacon, telemetry) | **No** |
| DNS resolution from the binary | **No** |
| Outbound TCP/UDP sockets of any kind | **No** |
| SMB lateral movement (NotPetya / EternalBlue path) | **No** |
| WMI / DCOM remote execution | **No** |
| RDP / WinRM client | **No** |
| Tor, I2P, ZeroNet client | **No** |
| Cryptocurrency wallet exfiltration | **No** |
| Hard-coded URLs, onion addresses, BTC wallets, ransom emails | **No** |

The upstream README states this explicitly:
> OpenPetya does **NOT** include Command-and-Control (C2) functionality.

The source backs this up: no imports of `ws2_32.dll`, `winhttp.dll`,
`wininet.dll`, `mswsock.dll`, `dnsapi.dll`, `secur32.dll`, `schannel.dll`,
or any IRP-issuing network kernel API. The only IRP issued is to
`\Device\Harddisk0\DR0` (raw disk write).

**Consequence:** there is nothing on the wire to alert on during
execution. A Suricata rule cannot trigger on traffic that does not exist.

---

## What can theoretically be on the wire

Delivery only:

| Delivery vector | Plaintext on wire? | Suricata coverage |
|---|---|---|
| Browser download from github.com / codeload.github.com | No (TLS) | Only with TLS interception |
| `git clone https://...` | No (TLS) | Only with TLS interception |
| `curl` / `wget` against github.com over HTTPS | No (TLS) | Only with TLS interception |
| Internal mirror over plaintext HTTP | Yes | **Rules 1–8 in [openpetya-delivery-http.rules](openpetya-delivery-http.rules) cover this** |
| Lab/CTF environment over plaintext HTTP | Yes | Same |
| USB / OneDrive / Slack DM file share | No (out-of-band) | None possible |
| Email attachment (the dropper as `.exe` attached) | Sometimes plaintext SMTP, more often TLS | Partial via existing mail-AV / sandbox flow |
| Pre-staged on the host by another piece of malware (loader chain) | Out of scope | Detect the loader, not OpenPetya |

So the network-side coverage is real **only** for plaintext HTTP and
TLS-intercepted HTTPS. Everything else is out of reach of an NSM sensor.

---

## Where coverage actually comes from

Since the network layer is blind to almost everything OpenPetya does,
all real coverage is host-side. Mapped to the kill chain:

| Kill-chain step | Network coverage | **Real coverage** (host) |
|---|---|---|
| Delivery | [openpetya-delivery-http.rules](openpetya-delivery-http.rules) (situational) | [openpetya.yar](openpetya.yar) `OpenPetya_Source_Repository_v2` + `OpenPetya_Dropper_PE_v2` on file write |
| Installation (dropper launch) | None | [openpetya-sysmon.xml](openpetya-sysmon.xml) ProcessCreate rules + [openpetya.sigma.yml](openpetya.sigma.yml) rule 1 |
| Privilege adjust | None | [openpetya-sysmon.xml](openpetya-sysmon.xml) reinforcement; [prevention/](prevention/) ASR rule `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` |
| MBR / sector 0 overwrite | None | [openpetya-sysmon.xml](openpetya-sysmon.xml) RawAccessRead + [openpetya-defender.kql](openpetya-defender.kql) Q2 + [openpetya.sigma.yml](openpetya.sigma.yml) rule 2 + [prevention/](prevention/) IOAs/BIOCs |
| Stage-2 write to LBA 1–52 | None | Same as above |
| BSOD / forced reboot | None | [openpetya.sigma.yml](openpetya.sigma.yml) rule 3 (compound) + [openpetya-defender.kql](openpetya-defender.kql) Q4 |
| Pre-OS stage-2 execution | None possible | Pre-OS — out of host-OS reach. Covered by Secure Boot / TPM-measured boot / BitLocker / boot-sector hash baseline (see [openpetya-prevention.md](openpetya-prevention.md) §1) |
| MFT encryption | None | Same as above |
| Post-reboot ransom UI | None | Same as above |

Network detection contributes essentially nothing to the right-hand
column. **Don't budget for it; budget for the host column.**

---

## When the gap analysis does NOT apply — Petya forks with propagation

OpenPetya as published is non-propagating. A fork that bolts on a
spreader (the original NotPetya did exactly this via SMB/EternalBlue
+ Mimikatz-derived credential theft) becomes a different beast and
suddenly has lots of wire signal.

If you operate in an environment where the realistic threat is a
**NotPetya-style fork**, enable these existing ET/community rules
alongside the host coverage:

| Threat | Recommended ET rules / coverage |
|---|---|
| EternalBlue SMB exploit | `ET EXPLOIT` SIDs 2024297, 2024298, 2024299, 2024430 (and successors) |
| SMB lateral copy | ET OPEN SMB ruleset (file copy via SMB share enumeration) |
| Mimikatz over WMI | Sigma `proc_creation_win_lsass_access_*` family |
| psexec / wmic lateral | Sigma `proc_creation_win_psexec_*` + Sysmon EventID 1 with `ParentImage` = `psexec64.exe` |
| Pass-the-Hash | Windows Event 4624 logon-type-3 with NTLM and unexpected source IP |

These are **not** Petya-family rules — they cover the propagation
layer that a Petya **fork** would borrow. Pair them with the host
detections in this pack and you cover the realistic threat surface
for any Petya-class variant whether or not it propagates.

---

## What about JA3 / JA3S / TLS-fingerprint-based detection?

JA3/JA3S fingerprint the TLS handshake from the *client library*, not
the malware. OpenPetya has no TLS client at all, so it cannot have a
JA3. The fingerprint that appears on the wire during delivery is the
fingerprint of whatever downloaded the file — `git.exe`, `curl.exe`,
`Edge`, `Firefox`. Those fingerprints are dominated by hundreds of
millions of benign legitimate connections daily and are useless as a
malware-family signal.

**JA3 is not a solution to the OpenPetya network gap.** It is a
solution to a different problem (fingerprinting malware that *does*
make TLS connections — e.g. Cobalt Strike, IcedID, BumbleBee).

---

## What this means for your detection-engineering posture

1. **Don't write more Suricata for this family.** Anything you produce
   either duplicates the existing situational rules or claims coverage
   it can't deliver.
2. **Invest in the host telemetry layer.** That is the entire battle
   for this family. The host rules in this pack already cover the
   kill chain end-to-end.
3. **Invest in boot-integrity controls.** Stage-2 runs pre-OS, beyond
   the reach of EDR. Secure Boot / TPM-measured boot / BitLocker /
   boot-sector hash baseline (see [openpetya-prevention.md](openpetya-prevention.md) §1)
   are the only controls that touch that phase.
4. **If you care about Petya forks with spreaders, enable the ET
   propagation rules** listed above. They cover the layer a real
   Petya fork would add; OpenPetya itself doesn't need them.
5. **Be honest with stakeholders.** "We have no network signature
   for this family because the family has no network surface" is a
   correct and defensible posture. It is not a coverage failure.
