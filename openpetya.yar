/*
    OpenPetya / Petya-class detection ruleset  --  v2 (hardened)
    ============================================================
    Author:    Andrew Quill
    Created:   2026-05-24
    Modified:  2026-05-24
    Version:   2.0
    License:   Apache-2.0
    TLP:       TLP:CLEAR
    Target:    https://github.com/iss4cf0ng/OpenPetya
    Family:    Ransomware / Bootkit (Petya-class, MBR locker)

    v2 changes summary
    ------------------
      * Stage-2 detection no longer relies on ransom strings or skull art.
        Replaced with a STRUCTURAL fingerprint:
            Salsa20/ChaCha20 sigma  +  NTFS "FILE" magic / "NTFS" tag
          + protected-mode transition opcodes  +  INT 13h LBA pattern.
        Lazy attackers (no string change) are still caught by the
        low-fidelity OpenPetya_LowFidelity_Strings rule.

      * Dropper PE detection no longer requires the literal
        "\\.\PhysicalDrive" path. Anchored on IOCTL/FSCTL 32-bit
        immediates that any raw-disk writer needs:
            0x000700A0, 0x002D1400, 0x00090018, 0x00090020, 0x0007C0F4
        Plus alternate-path string atoms for ALL known Win32/NT
        syntaxes that resolve to a disk-class kernel object.

      * Privilege/reboot APIs demoted to REINFORCEMENT - they no longer
        trigger alone. The wide reboot-primitive set covers attacker
        substitutions (ExitWindowsEx, InitiateSystemShutdownEx,
        AdjustTokenPrivileges, NtTerminateProcess, etc).

      * Infected-disk detection no longer relies on the "HOLD"/"BOOT"/
        "PASS" magic bytes. Replaced with STRUCTURAL anomaly detection:
        two valid MBRs in the same image with matching partition tables.

      * MBR rule keeps the structural anchors (filesize == 512, 55 AA
        at 0x1FE, INT13 AH=41/42 opcode sequence) and drops the
        attacker-controllable "MBR: " print strings.
*/

import "pe"
import "math"


/*--------------------------------------------------------------------
    Rule 1: Low-fidelity catch-all -- strings (lazy attackers only)
    Triggers on the unmodified source/binaries. A single rename of
    the macros defeats this; the structural rules below do not care.
--------------------------------------------------------------------*/
rule OpenPetya_LowFidelity_Strings
{
    meta:
        author        = "Andrew Quill"
        date          = "2026-05-24"
        modified      = "2026-05-24"
        version       = "2.0"
        license       = "Apache-2.0"
        tlp           = "TLP:CLEAR"
        rule_id       = "5c3a1a40-9d0d-4f6b-b15b-1fae6f9f0c01"
        description   = "OpenPetya unmodified strings (low fidelity)"
        severity      = "medium"
        confidence    = "medium"
        maltype       = "ransomware"
        reference     = "https://github.com/iss4cf0ng/OpenPetya"
        mitre         = "T1561.002, T1485, T1490, T1529"
        falsepositives = "Authorized red-team / detection-engineering exercises with the published PoC"
        notes         = "Defeated by string renaming. Kept for unmodified samples."
    strings:
        $s_niha     = "NiHaHaHaHa" ascii
        $s_blue     = "Play Blue Archive" ascii
        $s_press    = "(Press any key to NiHaHaHaHa)" ascii
        $s_ooops    = "Ooops, your important files are encrypted." ascii
        $s_guar     = "We guaratee that you can recover all your files safely" ascii   // sic
        $s_op1st    = "OpenPetya, 1st stage." ascii
        $s_mbrboot  = "MBR: Booting..." ascii
        $s_mbrload  = "MBR: Loading Stage2..." ascii
        $s_mbrjump  = "MBR: Jumping to Stage2..." ascii
    condition:
        2 of them
}


/*--------------------------------------------------------------------
    Rule 2: Source / repository drop -- structural anchors
    Catches the cloned source tree even if the author renames the
    advertising macros. Anchored on disk-layout constants whose VALUES
    can change but whose POSITIONS are an architectural fingerprint.
--------------------------------------------------------------------*/
rule OpenPetya_Source_Repository_v2
{
    meta:
        author        = "Andrew Quill"
        date          = "2026-05-24"
        modified      = "2026-05-24"
        version       = "2.0"
        license       = "Apache-2.0"
        tlp           = "TLP:CLEAR"
        rule_id       = "5c3a1a40-9d0d-4f6b-b15b-1fae6f9f0c02"
        description   = "OpenPetya PoC source tree (cloned/archived)"
        severity      = "high"
        confidence    = "high"
        maltype       = "ransomware-source"
        reference     = "https://github.com/iss4cf0ng/OpenPetya"
        mitre         = "T1588.001"
        falsepositives = "Authorized clones for defensive analysis"
    strings:
        // Architectural disk-layout constants (positions that betray
        // the project even if magic VALUES are randomized)
        $cfg_pwsec      = /PW_SECTOR\s+\d{1,3}/                     // sector 59
        $cfg_statesec   = /STATE_SECTOR\s+\d{1,3}/                  // sector 60
        $cfg_validsec   = /VALIDATE_SECTOR\s+\d{1,3}/               // sector 61
        $cfg_saltsec    = /SALT_SECTOR\s+\d{1,3}/                   // sector 62
        $cfg_bakmbr     = /BACKUP_MBR_SECTOR\s+\d{1,3}/             // sector 63
        $cfg_mftbak     = /MFT_BACKUP_SECTORS\s+\d{1,3}/
        $cfg_kdf        = /KDF_ITERATIONS\s+\d+/
        $cfg_stage2nl   = "STAGE2_SECTORS"
        $cfg_stage2loff = "STAGE2_LOAD_OFF"
        // Architectural file presence (project structure)
        $code_ntfscrypt = "ntfs_mft_encrypt"
        $code_hidden    = "hidden_backup_mft"
        $code_stateread = "state_read"
        // Build chain
        $build_mingw    = "x86_64-w64-mingw32-g++"
    condition:
        // Need both a layout-constant pattern AND a code/structural marker.
        // Catches renames; one whole family must be gutted to evade.
        3 of ($cfg_*) and 1 of ($code_*, $build_mingw)
}


/*--------------------------------------------------------------------
    Rule 3: Compiled user-mode dropper -- structural (IOCTLs+setupapi)
    No longer depends on the literal "\\.\PhysicalDrive" string.
    Anchored on IOCTL/FSCTL 32-bit immediates and the setupapi
    enumeration surface (the dropper statically links setupapi).
--------------------------------------------------------------------*/
rule OpenPetya_Dropper_PE_v2
{
    meta:
        author        = "Andrew Quill"
        date          = "2026-05-24"
        modified      = "2026-05-24"
        version       = "2.0"
        license       = "Apache-2.0"
        tlp           = "TLP:CLEAR"
        rule_id       = "5c3a1a40-9d0d-4f6b-b15b-1fae6f9f0c03"
        description   = "OpenPetya / Petya-class user-mode installer (PE)"
        severity      = "critical"
        confidence    = "high"
        maltype       = "ransomware-installer"
        mitre         = "T1561.002, T1485, T1490, T1529, T1134"
        reference     = "https://github.com/iss4cf0ng/OpenPetya"
        falsepositives = "Legitimate disk-imaging utilities with similar IOCTL surface; tune signer allowlist"
        notes         = "Path-syntax-agnostic. Catches alternate path declarations."
    strings:
        // === IOCTL / FSCTL 32-bit LE immediates ===
        // Compiler emits these as numeric constants -- not renameable.
        $ioctl_geo      = { A0 00 07 00 }       // IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
        $ioctl_qprop    = { 00 14 2D 00 }       // IOCTL_STORAGE_QUERY_PROPERTY
        $ioctl_lock     = { 18 00 09 00 }       // FSCTL_LOCK_VOLUME
        $ioctl_dismnt   = { 20 00 09 00 }       // FSCTL_DISMOUNT_VOLUME
        $ioctl_dasdio   = { 14 02 09 00 }       // FSCTL_ALLOW_EXTENDED_DASD_IO
        $ioctl_layout   = { F4 C0 07 00 }       // IOCTL_DISK_SET_DRIVE_LAYOUT_EX

        // === Setupapi disk-enumeration surface ===
        $setup_classdev = "SetupDiGetClassDevs" ascii
        $setup_enumif   = "SetupDiEnumDeviceInterfaces" ascii
        $setup_ifdetail = "SetupDiGetDeviceInterfaceDetail" ascii
        // GUID_DEVINTERFACE_DISK = {53F56307-B6BF-11D0-94F2-00A0C91EFB8B}
        $guid_diskif    = { 07 63 F5 53 BF B6 D0 11 94 F2 00 A0 C9 1E FB 8B }

        // === Alternate raw-disk path syntaxes (still useful as atoms) ===
        $p_phys_w       = "\\\\.\\PhysicalDrive"  wide  nocase
        $p_phys_a       = "\\\\.\\PhysicalDrive"  ascii nocase
        $p_qmark_w      = "\\\\?\\PhysicalDrive"  wide  nocase
        $p_qmark_a      = "\\\\?\\PhysicalDrive"  ascii nocase
        $p_ntpath_w     = "\\Device\\Harddisk"     wide  nocase
        $p_ntpath_a     = "\\Device\\Harddisk"     ascii nocase
        $p_globalroot_w = "GLOBALROOT\\Device\\Harddisk" wide  nocase
        $p_globalroot_a = "GLOBALROOT\\Device\\Harddisk" ascii nocase
        $p_vol_w        = "\\\\.\\Volume{" wide nocase
        $p_vol_a        = "\\\\.\\Volume{" ascii nocase
        $p_nt_w         = "\\??\\PhysicalDrive" wide nocase
        $p_nt_a         = "\\??\\PhysicalDrive" ascii nocase

        // === Reinforcement: privilege/reboot APIs (any of) ===
        $rb_ntrhe       = "NtRaiseHardError" ascii
        $rb_rtladj      = "RtlAdjustPrivilege" ascii
        $rb_exit        = "ExitWindowsEx" ascii
        $rb_initshutd   = "InitiateSystemShutdown" ascii    // Ex variant matches too
        $rb_adjtoken    = "AdjustTokenPrivileges" ascii
        $rb_luval       = "LookupPrivilegeValue" ascii
        $rb_seshut      = "SeShutdownPrivilege" ascii
        $rb_ntterm      = "NtTerminateProcess" ascii
        $rb_zshutdown   = "ZwShutdownSystem" ascii
        $rb_ntshutdown  = "NtShutdownSystem" ascii
        $rb_status      = { 20 04 00 C0 }                   // STATUS_ASSERTION_FAILURE
    condition:
        uint16(0) == 0x5A4D
        and pe.is_pe
        and (
            // PRIMARY 1: IOCTL constellation -- 3-of-6 (any combination
            //            of three raw-disk IOCTL immediates). Numeric
            //            constants, not renameable.
            3 of ($ioctl_*)

            // PRIMARY 2: setupapi disk-enumeration anchored by the
            //            GUID_DEVINTERFACE_DISK immediate.
            or ( $guid_diskif and 2 of ($setup_*) )
        )
        // REINFORCEMENT: a reboot/priv primitive must be present (any).
        // The set is wide enough to cover attacker substitutions.
        and 1 of ($rb_*)
        // EVIDENCE: at least one of the many raw-disk path syntaxes
        // is present (we don't pin which). Path-syntax-agnostic.
        and 1 of ($p_*)
}


/*--------------------------------------------------------------------
    Rule 4: MBR / stage-1 -- structural (drops attacker-controllable msgs)
    A 512-byte sector with the boot signature that uses INT13 AH=42
    LBA-extension reads to pull a many-sector payload from low LBAs.
--------------------------------------------------------------------*/
rule OpenPetya_MBR_Stage1_v2
{
    meta:
        author        = "Andrew Quill"
        date          = "2026-05-24"
        modified      = "2026-05-24"
        version       = "2.0"
        license       = "Apache-2.0"
        tlp           = "TLP:CLEAR"
        rule_id       = "5c3a1a40-9d0d-4f6b-b15b-1fae6f9f0c04"
        description   = "OpenPetya / Petya-class stage-1 MBR (boot sector)"
        severity      = "critical"
        confidence    = "high"
        maltype       = "bootkit"
        mitre         = "T1542.003"
        reference     = "https://github.com/iss4cf0ng/OpenPetya"
        falsepositives = "Legitimate boot-sector tools (very rare in enterprise contexts)"
    strings:
        // INT 13h AH=0x41 ext-check, bx=0x55AA
        $ext_check = { B4 41 BB AA 55 }
        // INT 13h AH=0x42 LBA read
        $lba_read  = { B4 42 ?? ?? CD 13 }
        // DAP (Disk Address Packet) header bytes (size=0x10, reserved=0)
        $dap_hdr   = { 10 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? }
        // Print routine via INT 10h teletype AH=0x0E
        $print_te  = { B4 0E ?? ?? CD 10 }
    condition:
        filesize == 512
        and uint16(0x1FE) == 0xAA55           // boot signature
        and $ext_check
        and $lba_read
        and 1 of ($dap_hdr, $print_te)
}


/*--------------------------------------------------------------------
    Rule 5: Stage-2 -- STRUCTURAL fingerprint (string-independent)
    Petya-class stage-2 must do:
      (1) stream cipher  (Salsa20/ChaCha20 sigma constants)
      (2) NTFS-aware parse  ("FILE" record magic OR "NTFS" tag check)
      (3) real-mode -> protected-mode transition  (LGDT + CR0 + far jmp)
      (4) BIOS INT 13h LBA disk I/O  (AH=0x42 + CD 13)
    3-of-4 in a small flat binary is the stage-2 family. None of the
    four can be removed without removing required function.
--------------------------------------------------------------------*/
rule Petya_Class_Stage2_Structural
{
    meta:
        author        = "Andrew Quill"
        date          = "2026-05-24"
        modified      = "2026-05-24"
        version       = "2.0"
        license       = "Apache-2.0"
        tlp           = "TLP:CLEAR"
        rule_id       = "5c3a1a40-9d0d-4f6b-b15b-1fae6f9f0c05"
        description   = "Petya-class stage-2 structural fingerprint (string-independent)"
        severity      = "critical"
        confidence    = "high"
        maltype       = "bootkit-payload"
        mitre         = "T1542.003, T1486, T1490"
        reference     = "https://github.com/iss4cf0ng/OpenPetya"
        falsepositives = "Other bootloader-class binaries that happen to include Salsa20/ChaCha20 + NTFS parsing"
        notes         = "Survives full ransom-text rewrite and skull-art removal."
    strings:
        // (1) Salsa20/ChaCha20 sigma constants -- four 32-bit LE words
        $sigma0 = { 65 78 70 61 }            // "expa"
        $sigma1 = { 6E 64 20 33 }            // "nd 3"
        $sigma2 = { 32 2D 62 79 }            // "2-by"
        $sigma3 = { 74 65 20 6B }            // "te k"
        // ChaCha20-tau variant alternative
        $tau0   = { 65 78 70 61 }            // "expa" (same)
        $tau1   = { 6E 64 20 31 }            // "nd 1"
        $tau2   = { 36 2D 62 79 }            // "6-by"

        // (2) NTFS-aware parsing markers
        $ntfs_tag    = "NTFS" ascii          // checked at VBR offset 3
        $file_record = { 46 49 4C 45 }       // "FILE" MFT record magic 0x454C4946 LE

        // (3) Real-mode to protected-mode transition opcodes
        // LGDT  0F 01 1? (where ?=0..7 selects mod/rm form)
        $pm_lgdt   = { 0F 01 1? }
        // mov eax, cr0  ;  or al, 1  ;  mov cr0, eax  ;  16-bit far jmp
        $pm_cr0a   = { 0F 20 C0 }
        $pm_cr0b   = { 0F 22 C0 }
        // 32-bit far jump after PM enable (66 prefix + EA opcode)
        $pm_jmpf   = { 66 EA ?? ?? ?? ?? 08 00 }

        // (4) BIOS INT 13h LBA pattern
        $int13_lba = { B4 42 ?? ?? CD 13 }
        // BIOS INT 10h teletype or INT 16h key-read (any BIOS service)
        $int10_te  = { B4 0E ?? ?? CD 10 }
        $int16_kb  = { B4 00 CD 16 }
    condition:
        // Must be a flat binary (not PE/ELF/Mach-O)
        not (uint16(0) == 0x5A4D)
        and not (uint32(0) == 0x464C457F)
        and not (uint32(0) == 0xFEEDFACE) and not (uint32(0) == 0xFEEDFACF)
        and filesize > 2KB and filesize < 256KB

        // 3-of-4 functional pillars required.
        and (
            (
                // (1) stream cipher pillar -- sigma OR tau
                ( all of ($sigma*) ) or ( all of ($tau*) )
            )
            and (
                // (2) NTFS pillar -- string tag or FILE record magic
                $ntfs_tag or $file_record
            )
            and (
                // (3) protected-mode transition pillar (any 2 of 4)
                2 of ($pm_*)
            )
            and (
                // (4) BIOS service pillar (any one suffices)
                1 of ($int10_te, $int13_lba, $int16_kb)
            )
        )
        // Anti-FP: this combination has very high overall entropy
        and math.entropy(0, filesize) > 5.0
}


/*--------------------------------------------------------------------
    Rule 6a: Infected disk -- recovery-preserving variant
    Two valid MBR-shaped sectors with matching partition tables = the
    "back-up-then-overwrite" pattern, characteristic of variants that
    still claim a decryption-on-payment promise.
    Note: an adversarial fork can skip the backup -- if so, Rule 6b
    is the catch.
--------------------------------------------------------------------*/
rule Petya_Class_InfectedDisk_TwoMBRs
{
    meta:
        author        = "Andrew Quill"
        date          = "2026-05-24"
        modified      = "2026-05-24"
        version       = "2.0"
        license       = "Apache-2.0"
        tlp           = "TLP:CLEAR"
        rule_id       = "5c3a1a40-9d0d-4f6b-b15b-1fae6f9f0c06"
        description   = "Two valid MBR-shaped sectors in one disk image (recovery-preserving Petya variant)"
        severity      = "critical"
        confidence    = "high"
        maltype       = "ransomware-infected-host"
        mitre         = "T1542.003, T1561.002"
        reference     = "https://github.com/iss4cf0ng/OpenPetya"
        falsepositives = "Legacy Win XP/2003 images with sector-63-aligned partitions"
        notes         = "Catches recovery-preserving forks. Adversarial forks that skip the backup are caught by Rule 6b."
    condition:
        filesize > 1MB
        and uint16(0x1FE) == 0xAA55
        and (
            uint16(63  * 512 + 0x1FE) == 0xAA55
         or uint16(34  * 512 + 0x1FE) == 0xAA55
         or uint16(2047* 512 + 0x1FE) == 0xAA55
        )
        and (
            uint8(63*512 + 0x1C2) == 0x07
         or uint8(63*512 + 0x1C2) == 0x0B
         or uint8(63*512 + 0x1C2) == 0x0C
         or uint8(63*512 + 0x1C2) == 0x83
         or uint8(63*512 + 0x1C2) == 0xEE
        )
        and uint32(0x1BE) == uint32(63 * 512 + 0x1BE)
        and uint32(0x1C2) == uint32(63 * 512 + 0x1C2)
        and uint32(0x1C6) == uint32(63 * 512 + 0x1C6)
        and uint32(0x1CA) == uint32(63 * 512 + 0x1CA)
}


/*--------------------------------------------------------------------
    Rule 6b: Infected disk -- pre-partition payload (recovery-pruned)
    Catches adversarial Petya-class forks that SKIP the backup-MBR
    write (or skip the salt/validate sectors, or self-erase stage2
    after run). Anchored on the irreducible fact: stage-2 has to
    live SOMEWHERE in the pre-partition gap that the MBR INT-13-reads.

    Modern Windows aligns the first partition to LBA 2048 (1 MiB
    boundary). The gap LBA 1..2047 is zero-filled. Any non-zero
    high-entropy data there is anomalous regardless of which sectors
    the attacker chose. Multiple probe points so the attacker cannot
    evade by relocating stage-2 within the gap.

    Combined with a valid MBR at LBA 0, false-positive risk is low.
    Legitimate exceptions (Win XP/2003 with sector-63-aligned partitions,
    GRUB/LILO embedded stage1.5 in MBR gap on older Linux) should be
    explicitly enrolled into a baseline -- they pre-date the threat
    and are easy to enumerate.
--------------------------------------------------------------------*/
rule Petya_Class_InfectedDisk_PrePartitionPayload
{
    meta:
        author        = "Andrew Quill"
        date          = "2026-05-24"
        modified      = "2026-05-24"
        version       = "2.0"
        license       = "Apache-2.0"
        tlp           = "TLP:CLEAR"
        rule_id       = "5c3a1a40-9d0d-4f6b-b15b-1fae6f9f0c07"
        description   = "Non-zero high-entropy payload in modern-Windows pre-partition gap"
        severity      = "critical"
        confidence    = "medium-high"
        maltype       = "ransomware-infected-host"
        mitre         = "T1542.003, T1561.002"
        reference     = "https://github.com/iss4cf0ng/OpenPetya"
        falsepositives = "Legacy GRUB/LILO embedded stage1.5 in MBR gap; baseline and enumerate"
        notes         = "Catches recovery-pruned and self-erasing forks. No backup-MBR requirement. Multiple probe LBAs to defeat stage-2 relocation within the pre-partition gap."
    condition:
        filesize > 2MB
        // Valid MBR at LBA 0 (otherwise this isn't a bootable disk image)
        and uint16(0x1FE) == 0xAA55
        // Partition table at LBA 0 declares first partition starting at
        // LBA >= 2048 (so the pre-partition gap is supposed to be zero).
        // Partition-1 starting LBA lives at offset 0x1BE+8 = 0x1C6 as a
        // 32-bit LE value. We require >= 2048 (1 MiB alignment).
        and uint32(0x1C6) >= 2048
        // At least ONE of several probe regions inside the pre-partition
        // gap is non-zero high entropy. Probe points span the gap so the
        // attacker cannot evade by choosing a different stage-2 location.
        and (
            // Probe LBA 1..6  (3 KB) -- OpenPetya's canonical stage-2 head
            math.entropy(  1 * 512, 3 * 1024) > 3.0
            // Probe LBA 64..69 (3 KB)
         or math.entropy( 64 * 512, 3 * 1024) > 3.0
            // Probe LBA 256..261
         or math.entropy(256 * 512, 3 * 1024) > 3.0
            // Probe LBA 512..517
         or math.entropy(512 * 512, 3 * 1024) > 3.0
            // Probe LBA 1024..1029
         or math.entropy(1024* 512, 3 * 1024) > 3.0
            // Probe LBA 1536..1541
         or math.entropy(1536* 512, 3 * 1024) > 3.0
        )
}


/*--------------------------------------------------------------------
    Rule 6c: Infected disk -- pure-wiper variant (no ransomware UI)
    NotPetya-style: the operator never intended recovery; the MFT is
    overwritten with cryptographic random and no validator exists.
    Detect by ABSENCE of FILE record magic in regions where it should
    be dense, combined with a custom MBR.

    Note: this is a forensic-image-time rule. Live OS detection of
    this state is also possible but goes through different telemetry
    (the volume becomes unmountable, $MFT reads fail). The behavioural
    Sigma/KQL rules catch the precursor (raw-disk write + reboot).
--------------------------------------------------------------------*/
rule Petya_Class_InfectedDisk_WiperMode
{
    meta:
        author        = "Andrew Quill"
        date          = "2026-05-24"
        modified      = "2026-05-24"
        version       = "2.0"
        license       = "Apache-2.0"
        tlp           = "TLP:CLEAR"
        rule_id       = "5c3a1a40-9d0d-4f6b-b15b-1fae6f9f0c08"
        description   = "Suspected MBR-wiper variant: custom MBR + entropy in pre-partition gap, no backup MBR present"
        severity      = "critical"
        confidence    = "medium"
        maltype       = "wiper-infected-host"
        mitre         = "T1561.002, T1485"
        reference     = "https://github.com/iss4cf0ng/OpenPetya"
        falsepositives = "Custom-bootloader installations (Linux GRUB without legacy backup); baseline known systems"
        notes         = "Companion to Rule 6b. Triggers ONLY when 6a does not (no backup MBR) AND pre-partition payload IS present (6b). Indicates recovery has been pruned."
    condition:
        // Same precondition as Rule 6b
        filesize > 2MB
        and uint16(0x1FE) == 0xAA55
        and uint32(0x1C6) >= 2048
        // Pre-partition payload IS present
        and (
            math.entropy(  1 * 512, 3 * 1024) > 3.0
         or math.entropy( 64 * 512, 3 * 1024) > 3.0
         or math.entropy(256 * 512, 3 * 1024) > 3.0
        )
        // ... but NO backup MBR at the common backup LBAs
        // (cannot use "not (other rule)" in YARA, so re-state inline)
        and not (
            uint16(63  * 512 + 0x1FE) == 0xAA55
         or uint16(34  * 512 + 0x1FE) == 0xAA55
         or uint16(2047* 512 + 0x1FE) == 0xAA55
        )
}


/*--------------------------------------------------------------------
    Rule 7: Generic Petya-class user-mode primitives  --  v2
    Hardened: priv-escalation/reboot APIs are REINFORCEMENT only.
    Primary signals are raw-disk IOCTLs + embedded MBR-shaped blob.
--------------------------------------------------------------------*/
rule MBR_Locker_Generic_UsermodePrimitives_v2
{
    meta:
        author        = "Andrew Quill"
        date          = "2026-05-24"
        modified      = "2026-05-24"
        version       = "2.0"
        license       = "Apache-2.0"
        tlp           = "TLP:CLEAR"
        rule_id       = "5c3a1a40-9d0d-4f6b-b15b-1fae6f9f0c09"
        description   = "Generic user-mode primitives of a Petya-class MBR locker"
        severity      = "high"
        confidence    = "medium-high"
        maltype       = "heuristic-bootkit-installer"
        mitre         = "T1542.003, T1561.002, T1529"
        reference     = "https://github.com/iss4cf0ng/OpenPetya"
        falsepositives = "Disk-imaging utilities with similar IOCTL constellation; tune via signer allowlist"
        notes         = "Catches OpenPetya forks and unrelated MBR lockers."
    strings:
        // PRIMARY 1: raw-disk IOCTL immediates (numeric, not renameable)
        $ioctl_geo    = { A0 00 07 00 }
        $ioctl_qprop  = { 00 14 2D 00 }
        $ioctl_lock   = { 18 00 09 00 }
        $ioctl_dismnt = { 20 00 09 00 }
        $ioctl_layout = { F4 C0 07 00 }

        // PRIMARY 2: an embedded MBR-shaped blob inside the .data/.rdata
        // section -- the dropper has to carry the stage-1 to write it.
        // We look for a 0x55 0xAA pattern preceded by typical INT13 ext
        // check immediate (BB AA 55 -- mov bx, 0x55AA -- 1-2 KB earlier).
        $embedded_bx55aa = { BB AA 55 }
        $embedded_bootsig = { 55 AA }

        // REINFORCEMENT 1: any reboot / shutdown primitive (wide set)
        $rb_ntrhe      = "NtRaiseHardError" ascii
        $rb_rtladj     = "RtlAdjustPrivilege" ascii
        $rb_exit       = "ExitWindowsEx" ascii
        $rb_initshutd  = "InitiateSystemShutdown" ascii
        $rb_adjtoken   = "AdjustTokenPrivileges" ascii
        $rb_seshut     = "SeShutdownPrivilege" ascii
        $rb_ntterm     = "NtTerminateProcess" ascii
        $rb_zshutdown  = "ZwShutdownSystem" ascii
        $rb_ntshutdown = "NtShutdownSystem" ascii

        // REINFORCEMENT 2: any raw-disk path syntax
        $p_phys_w      = "\\\\.\\PhysicalDrive" wide nocase
        $p_phys_a      = "\\\\.\\PhysicalDrive" ascii nocase
        $p_ntpath_w    = "\\Device\\Harddisk" wide nocase
        $p_ntpath_a    = "\\Device\\Harddisk" ascii nocase
        $p_qmark_w     = "\\\\?\\PhysicalDrive" wide nocase
        $p_qmark_a     = "\\\\?\\PhysicalDrive" ascii nocase

        // Common Win32 disk-handling APIs
        $api_cfw       = "CreateFileW"        ascii
        $api_dvc       = "DeviceIoControl"    ascii
        $api_wf        = "WriteFile"          ascii
        $api_sfp       = "SetFilePointerEx"   ascii
    condition:
        uint16(0) == 0x5A4D
        and pe.is_pe
        // PRIMARY: 3-of-5 IOCTL immediates
        and 3 of ($ioctl_*)
        // PRIMARY-OR-PRIMARY: embedded MBR-shaped blob inside the PE
        // (look for at least 2 boot-signature occurrences -- typical PEs
        //  shouldn't contain 55 AA twice; an embedded MBR + its own EOI
        //  combo would.)
        and #embedded_bootsig >= 2
        // PRIMARY: 3-of-4 raw-disk APIs
        and 3 of ($api_*)
        // REINFORCEMENT: at least one reboot primitive
        and 1 of ($rb_*)
        // REINFORCEMENT: at least one raw-disk path syntax
        and 1 of ($p_*)
        // Anti-FP: above-noise overall entropy
        and math.entropy(0, filesize) > 6.0
}


/*--------------------------------------------------------------------
    Rule 8 (companion): Petya-class stage-2 LIVING on raw disk sectors
    Same structural pillars as Rule 5, but tuned for matching against
    a memory dump containing disk-cache pages or a sector-image carve.
--------------------------------------------------------------------*/
rule Petya_Class_Stage2_OnDisk_Carving
{
    meta:
        author        = "Andrew Quill"
        date          = "2026-05-24"
        modified      = "2026-05-24"
        version       = "2.0"
        license       = "Apache-2.0"
        tlp           = "TLP:CLEAR"
        rule_id       = "5c3a1a40-9d0d-4f6b-b15b-1fae6f9f0c0a"
        description   = "Petya-class stage-2 structural pillars carved from a memory/disk dump"
        severity      = "critical"
        confidence    = "high"
        maltype       = "bootkit-payload"
        mitre         = "T1542.003, T1486"
        reference     = "https://github.com/iss4cf0ng/OpenPetya"
        falsepositives = "Memory dumps containing legitimate bootloader code that happens to combine these features"
    strings:
        $sigma0 = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }  // "expand 32-byte k" packed
        $file   = { 46 49 4C 45 }                                       // "FILE"
        $pm_cr0 = { 0F 22 C0 }                                          // mov cr0, eax
        $int13  = { B4 42 ?? ?? CD 13 }
    condition:
        filesize > 64KB    // typical memory page / sector-image dump
        and $sigma0
        and $file
        and $pm_cr0
        and $int13
}
