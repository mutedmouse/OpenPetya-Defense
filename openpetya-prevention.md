# OpenPetya / Petya-class MBR Locker — Defensive Hardening

| | |
|---|---|
| **Author** | Andrew Quill |
| **Created** | 2026-05-24 |
| **Modified** | 2026-05-24 |
| **Version** | 2.0 |
| **License** | Apache-2.0 |
| **TLP** | TLP:CLEAR |
| **Reference** | https://github.com/iss4cf0ng/OpenPetya |
| **MITRE ATT&CK** | T1561.002, T1485, T1490, T1529, T1542.003, T1134 |

This document pairs with the detection ruleset (`openpetya.yar`,
`openpetya-sysmon.xml`, `openpetya-defender.kql`, `openpetya.sigma.yml`,
`openpetya-delivery-http.rules`, `openpetya-network-gap.md`). The detections tell you when something **happens**; this
document is about making it **not happen** in the first place, organized by
how much the control actually costs to defeat.

The ordering is **descending strength** — the top controls survive
rebrand/recompile/payload-swap of the OpenPetya source. The lower controls
are useful enablers, not standalone defenses.

---

## 1. Boot-path integrity — eliminates the attack class

OpenPetya is a **legacy MBR / INT 13h** bootkit. On a host that does not
execute legacy boot code, the stage-1 MBR cannot run at all. The cost to
defeat this is "convert your malware into a UEFI bootkit" — that is a
materially different (and much harder) attack.

| Control | What it costs the attacker |
|---|---|
| **UEFI boot with CSM/Legacy boot disabled in firmware** | Stage-1 MBR is never loaded by firmware. Stage-2 is unreachable. Hard to bypass without firmware access. |
| **Secure Boot enabled, Microsoft 3rd-party CA disabled** | Attacker now needs a signed bootloader. |
| **TPM 2.0 + Measured Boot, PCRs 0–7 sealed to a key** | Any change to the MBR / VBR / boot manager changes PCR values; sealed secrets (e.g., BitLocker key) become unavailable. |
| **BitLocker with TPM-only or TPM+PIN protector** | After OpenPetya overwrites sector 0, on next boot the TPM measurements diverge; BitLocker enters recovery mode and refuses to release the key. The disk does not silently decrypt for the bootkit. |
| **Firmware admin password + locked-down setup menu** | Prevents physical-presence rollback to legacy boot. |
| **Boot-sector hash baseline + scheduled verification** | Stage-2 lives in LBAs 1–52 (or whatever the attacker chose in the pre-partition gap). Hash LBAs 0–2047 once on a known-clean machine; verify daily from a signed scheduled task or from a WinRE-served helper. Any drift is the entire pre-OS attack surface. **This is the dedicated standalone control for the stage-2 layer** — it does not depend on Secure Boot or TPM and complements both. |
| **Defender System Guard / Secured-Core PC features** on supported platforms | Hardware-rooted DRTM (Dynamic Root of Trust Measurement) attests boot-component identity to a remote verifier — turns drift into an enterprise alert rather than a local check. |

> **Verify on each endpoint**
> ```powershell
> Confirm-SecureBootUEFI                                    # True
> Get-BitLockerVolume -MountPoint C: | Select VolumeStatus, ProtectionStatus, KeyProtector
> (Get-Tpm).TpmReady                                        # True
> bcdedit /enum {bootmgr}                                   # path \EFI\Microsoft\Boot\bootmgfw.efi
> ```

---

## 2. Application control — denies execution of the dropper

`OpenPetya.exe` is built with `x86_64-w64-mingw32-g++` and is **not signed
by any publisher you trust**. A default-deny code-integrity policy blocks
it without needing to know the file exists.

| Control | Notes |
|---|---|
| **WDAC (Windows Defender Application Control)** in enforced mode, publisher-allowlist policy | Strongest. Survives renaming, repacking, and recompilation by an untrusted signer. |
| **AppLocker** with Publisher rules + Path rules denying user-writable directories (`%LOCALAPPDATA%`, `%TEMP%`, `Downloads\`, `Public\`) | Older but widely deployed. Defeats the common drop path. |
| **Smart App Control** (Windows 11 22H2+) | Adds Microsoft cloud reputation; low-prevalence binaries blocked. |
| **ASR rule: "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"** (GUID `01443614-cd74-433a-b99e-2ecdc07bfc25`) | Single rule that meaningfully degrades the entire delivery class. |
| **ASR rule: "Block executable content from email client and webmail"** (`be9ba2d9-53ea-4cdc-84e5-9b1eeee46550`) | Stops one common delivery vector. |
| **ASR rule: "Block all Office applications from creating child processes"** (`d4f940ab-401b-4efc-aadc-ad5f3c50688a`) | Stops macro -> dropper chain. |

> **Enable an ASR rule in Audit then Block:**
> ```powershell
> Set-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 `
>                  -AttackSurfaceReductionRules_Actions AuditMode      # then Enabled
> ```

---

## 3. Least privilege — denies the raw-disk primitive

`CreateFileW("\\.\PhysicalDrive0", GENERIC_WRITE, …)` requires **local
administrator** (specifically, membership in `BUILTIN\Administrators` or
the `SeManageVolumePrivilege` / SYSTEM token). Without elevation, the
dropper exits with `ERROR_ACCESS_DENIED` (5) at the very first I/O call.

| Control | What it blocks |
|---|---|
| **No interactive users in `BUILTIN\Administrators`** (LAPS-style design) | OpenPetya cannot open `\\.\PhysicalDrive*` for write. |
| **UAC set to "Always notify"**, with `EnableLUA=1`, `ConsentPromptBehaviorAdmin=2` | The dropper cannot silently elevate. |
| **Disable `SeShutdownPrivilege` for non-administrative users** via Group Policy (User Rights Assignment → "Shut down the system") | Defeats the `RtlAdjustPrivilege(19, …)` step that the BSOD primitive depends on. |
| **Credential Guard + LSA Protection (RunAsPPL)** | Limits credential theft that would enable lateral admin acquisition. |

---

## 4. Filesystem & data resilience — assume **no** in-band recovery

Assume the controls above fail. The blast radius is the boot disk: MBR,
VBR, first ~12 MB of MFT.

> **Do not plan on in-band recovery.** The unmodified OpenPetya happens to
> preserve enough on-disk state for partial restoration (original MBR at
> LBA 63, VBR backup near end-of-disk, MFT backup of 24 sectors). An
> adversarial fork removes any subset of this and you are left with no
> recovery path at all:
>
> - **Pruned backup**: dropper patched to skip the LBA-63 backup write →
>   original MBR is gone, partition layout must be rebuilt from scratch.
> - **Pruned validator**: stage-2 patched to skip salt/validate sectors →
>   even with the operator-chosen password, no key-validation tag exists,
>   so a "successful" decryption attempt produces gibberish silently.
> - **Self-erasing stage-2**: stage-2 zeros LBAs 1–52 after running →
>   forensic carving of the bootkit body is no longer possible.
> - **Wiper mode** (NotPetya semantics): the ransom UI is theatre; the
>   key is discarded or never derived; **no password recovers anything**.
>
> Treat the existence of an in-band backup as **a forensic gift if you
> get it, never a recovery plan you rely on**.

The only resilient answer is **out-of-band immutability**:

| Control | Notes |
|---|---|
| **Off-host immutable backups**, WORM / object-lock / S3-Object-Lock-Compliance / Azure Immutable Blob, retention longer than your incident-response window | The only mechanism that survives a wiper variant. Untouched by anything the victim machine can do. |
| **Backups verified by restore drill**, not job success | A "passing" backup that cannot be restored is worthless. Test quarterly against a clean-room rebuild target, not a same-environment "in-place restore". |
| **3-2-1-1-0 backup posture**: 3 copies, 2 media, 1 offsite, 1 immutable, 0 errors on last restore-test | Industry standard for ransomware-resilient backup. Anything weaker is gambling. |
| **System-image of `\EFI`** stored *outside* the host, with documented WinPE rebuild runbook | Concrete recovery procedure for the boot stack, distinct from data recovery. |
| **Air-gapped credential vault** with backup-system admin credentials and recovery keys (BitLocker recovery, TPM owner password, console-access creds) | Without these, you cannot restore even from good backups. Common ransomware mistake: backup credentials live on the encrypted DC. |

> **What you can and cannot do post-infection — be honest with stakeholders.**
>
> - **Cannot**: brute-force the Salsa20 key. The KDF is 1000 iterations
>   over a 16-byte salt. Even if the unmodified OpenPetya is in play, the
>   key search space is the operator-chosen-password space — out of reach
>   for any password not in a public wordlist.
> - **Cannot**: recover the MFT from VSS once it has been encrypted. The
>   shadow copies live in `$Volume:$DATA` which depends on `$MFT`; when
>   the MFT is unreadable, VSS is unreadable.
> - **Can** (with luck, against the *unmodified* OpenPetya only):
>   recover the original MBR and partition table from LBA 63, the VBR
>   from `disk_end − 3`, and the first 24 MFT records from
>   `disk_end − 27 .. disk_end − 4`. Use this in IR-triage, never in
>   capacity planning.
> - **Must**: restore from out-of-band immutable backup. Plan for it,
>   drill it, fund it.

### 4a. Wiper-variant playbook

If you observe the structural fingerprint of a *recovery-pruned* Petya
infection (YARA rule `Petya_Class_InfectedDisk_WiperMode` fires; no
backup MBR present; salt/validate sectors zero or random):

1. **Do not pay.** No key exists or no validator exists. Payment recovers
   nothing.
2. **Image the disk to read-only media** before any restoration. Treat
   the host as evidence — the structural signature is informative about
   the actor's intent (destruction vs. extortion).
3. **Rebuild from backup** to fresh hardware or a re-imaged disk. Do not
   attempt to "fix" the infected disk in place.
4. **Rotate every credential** that touched the host. Even though
   OpenPetya itself has no credential theft, the same actor may have run
   companion tools. Assume LSASS and SAM were dumped.
5. **Treat the partition layout as untrusted** even on the restored
   image — if the dropper patched the MBR, it may have also adjusted
   partition entries. Validate before mount.

---

## 5. Detection wiring — when the above fails, surface it fast

| Layer | Hook | Rule file |
|---|---|---|
| **EDR** | Raw disk write by untrusted image | `openpetya.sigma.yml` rule 2, `openpetya-defender.kql` Q2 |
| **EDR** | CLI argv fingerprint | `openpetya.sigma.yml` rule 1, `openpetya-defender.kql` Q1 |
| **EDR/SIEM** | Raw-disk write **then** forced reboot in 15m | `openpetya.sigma.yml` rule 3, `openpetya-defender.kql` Q4 |
| **Sysmon** | Process creation + RawAccessRead + FileCreate of `stage2.bin`/`mbr.bin` | `openpetya-sysmon.xml` |
| **File scan** | Source, dropper, MBR, stage2, infected disk | `openpetya.yar` |
| **Network (delivery only, situational)** | Plaintext-HTTP carving + TLS-intercepted body inspection | `openpetya-delivery-http.rules` |
| **Network (runtime)** | None — family has no network surface; see gap doc | `openpetya-network-gap.md` |

The single most useful **alerting** signal in production environments is
`Sigma rule 2 / KQL Q2` — "raw `\\.\PhysicalDrive*` write by anything that
is not on a small allowlist." Tune the allowlist once for your enterprise
backup agent and EDR sensor; then any new hit is high-confidence.

---

## 6. What will NOT save you from this

These are popular controls that **do not stop OpenPetya** specifically:

- **Controlled Folder Access** — protects user data directories, but
  `\\.\PhysicalDrive0` is not a folder; CFA is silent on it.
- **AV signatures on the source code** — easy to rename/refactor.
- **Volume Shadow Copies on the same disk** — the MFT corruption breaks
  the volume; VSS becomes unreadable.
- **Network segmentation** — there is no network component to segment.
- **Disabling SMBv1 / EternalBlue patching** — relevant to NotPetya, not
  to OpenPetya which has no propagation surface.
- **Detection rules that pin on `\\.\PhysicalDrive` literally** — any
  Win32/NT path syntax that resolves to a disk-class kernel object
  works (`\\?\PhysicalDrive`, `\??\PhysicalDrive`, `\Device\Harddisk*`,
  `\\.\GLOBALROOT\Device\Harddisk*`, `\\.\Volume{GUID}`,
  SetupApi interface paths, direct `NtCreateFile`). The detection
  rules in this pack match the **kernel-canonical** path, not the
  user-mode spelling — make sure yours do too.
- **Detection rules that pin on ransom-note strings** — these are user-
  controlled and trivially renamed. The detection rules in this pack
  retain string-based atoms as a low-fidelity catch for unmodified
  samples; the load-bearing detection is structural.
- **Plans that rely on the unmodified OpenPetya's backup-MBR-at-LBA-63
  semantics** — see §4. Adversarial forks remove the backup. Recovery
  plans that assume it are paper-thin.
- **Brute-force / known-plaintext attacks on the Salsa20 password** —
  Salsa20 is intact and the KDF is 1000 iterations over a 16-byte salt.
  Outside operator-password-in-wordlist scenarios, this is not feasible.

Listing these explicitly because organizations sometimes claim coverage
from a control that does not actually apply to this family.


## 7. Adversarial-revision history

This guidance is **v2**, hardened against the following defeats that
were identified by adversarial review of v1:

| Defeat | What v1 missed | v2 fix |
|---|---|---|
| Ransom-text rename | Stage-2 rule allowed `any of (ransom strings)` | Structural rule: Salsa20 sigma + NTFS `FILE` magic + PM transition + INT13 LBA |
| Alternate raw-disk path | Rules pinned `\\.\PhysicalDrive` literal | IOCTL/FSCTL 32-bit immediates + kernel-canonical `\Device\Harddisk*` + full path-syntax enumeration in atoms |
| Privilege APIs as primary | `NtRaiseHardError` AND `RtlAdjustPrivilege` required | Demoted to reinforcement; wide reboot-primitive set covers attacker substitutions |
| Stage-2 standalone need | No standalone signature OR prevention guidance | New structural YARA + new "boot-sector hash baseline" prevention control |
| Altered MBR magics | Rule required `HOLD`/`BOOT`/`PASS` magic bytes | Structural anomaly rule: two MBRs with matching partition tables |
| Recovery removal | §4 noted optional in-band recovery as if reliable | §4 rewritten: **assume no in-band recovery**; §4a "wiper-variant playbook" added; new YARA rule `Petya_Class_InfectedDisk_WiperMode` |
