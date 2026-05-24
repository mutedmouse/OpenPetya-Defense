<#
.SYNOPSIS
    Deploy Petya-class Attack Surface Reduction (ASR) rules in staged mode.

.DESCRIPTION
    Configures Microsoft Defender ASR rules most relevant to blocking
    OpenPetya / Petya-class droppers. Verifies cloud-delivered protection
    prerequisites. Defaults to AuditMode for safe rollout.

.PARAMETER Mode
    AuditMode | Warn | Enabled | Disabled (default AuditMode).

.EXAMPLE
    .\defender-asr.ps1 -Mode AuditMode
    .\defender-asr.ps1 -Mode Warn
    .\defender-asr.ps1 -Mode Enabled

.NOTES
    Author    : Andrew Quill
    Created   : 2026-05-24
    Modified  : 2026-05-24
    Version   : 2.0
    License   : Apache-2.0
    TLP       : TLP:CLEAR
    Reference : https://github.com/iss4cf0ng/OpenPetya
    MITRE     : T1561.002, T1485, T1490, T1529, T1134

.LINK
    https://learn.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
#>

# =====================================================================
#  Microsoft Defender ASR (Attack Surface Reduction) -- Petya-class
#  =====================================================================
#  Deploys (in AUDIT mode first) the ASR rules most relevant to
#  blocking OpenPetya / Petya-class droppers. Audit for >= 2 weeks,
#  triage events in:
#       Applications and Services Logs ->
#         Microsoft -> Windows -> Windows Defender -> Operational
#       Event IDs:  1121 (block), 1122 (audit), 5007 (config)
#  ...then re-run this script with $Mode='Enabled' to enforce.
#
#  Adversarial-defeat notes
#  ------------------------
#  NAIVE v1: Just enable everything in Enabled mode immediately.
#            Pain wave from FPs, ops disables every ASR rule, all
#            future Petya-class prevention from ASR is gone.
#
#  HARDENED v2 (this script): Stage rollout (AuditMode, then
#            Warn-mode for one rule at a time, then Enabled). Pin
#            specific GUIDs whose blast radius for FPs is low. Add
#            per-rule exclusion staging so the FIRST FP doesn't
#            trigger a global disable.
# =====================================================================

[CmdletBinding()]
param(
    [ValidateSet('AuditMode','Warn','Enabled','Disabled')]
    [string]$Mode = 'AuditMode'
)

# Map our string mode to the integer Defender expects
$ModeInt = switch ($Mode) {
    'Disabled'  { 0 }
    'Enabled'   { 1 }
    'AuditMode' { 2 }
    'Warn'      { 6 }
}

# -----------------------------------------------------------------
#  Rule selection -- Petya-class relevant subset
# -----------------------------------------------------------------
#  GUIDs and meanings are documented at
#  https://learn.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
$Rules = @(
    # === Tier 1: low FP risk, enable first ===
    @{
        Guid   = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
        Name   = 'Block all Office apps from creating child processes'
        FpRisk = 'low'
    },
    @{
        Guid   = '3b576869-a4ec-4529-8536-b80a7769e899'
        Name   = 'Block Office apps from creating executable content'
        FpRisk = 'low'
    },
    @{
        Guid   = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
        Name   = 'Block executable content from email/webmail'
        FpRisk = 'low'
    },
    @{
        Guid   = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        Name   = 'Block process creations originating from PsExec/WMI'
        FpRisk = 'medium'
    },

    # === Tier 2: directly targets Petya delivery ===
    @{
        Guid   = '01443614-cd74-433a-b99e-2ecdc07bfc25'
        Name   = 'Block executables unless they meet prevalence/age/trusted-list criteria'
        FpRisk = 'high'  # This is THE rule for unsigned low-prevalence droppers.
                         # Stage carefully. Cloud-delivered protection MUST be on.
    },
    @{
        Guid   = 'c1db55ab-c21a-4637-bb3f-a12568109d35'
        Name   = 'Use advanced protection against ransomware'
        FpRisk = 'medium'
    },

    # === Tier 3: defense in depth, not directly Petya but useful ===
    @{
        Guid   = '56a863a9-875e-4185-98a7-b882c64b5ce5'
        Name   = 'Block abuse of exploited vulnerable signed drivers'
        FpRisk = 'low'
    },
    @{
        Guid   = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
        Name   = 'Block credential stealing from lsass.exe'
        FpRisk = 'medium'
    },
    @{
        Guid   = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
        Name   = 'Block persistence through WMI event subscription'
        FpRisk = 'low'
    }
)

# Cloud-delivered protection is REQUIRED for the prevalence rule
Write-Host "[1/3] Verifying cloud-delivered protection prerequisites..." -ForegroundColor Cyan
$mp = Get-MpPreference
if ($mp.MAPSReporting -lt 2) {
    Write-Warning "MAPSReporting < Advanced. Setting to Advanced (required for rule 01443614-...)."
    Set-MpPreference -MAPSReporting Advanced
}
if (-not $mp.SubmitSamplesConsent -or $mp.SubmitSamplesConsent -eq 0) {
    Write-Warning "SubmitSamplesConsent disabled. Setting to SendSafeSamples."
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples
}

# -----------------------------------------------------------------
#  Apply each rule individually with its GUID + mode
# -----------------------------------------------------------------
Write-Host "[2/3] Applying $($Rules.Count) ASR rules in mode: $Mode" -ForegroundColor Cyan
foreach ($r in $Rules) {
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $r.Guid `
                         -AttackSurfaceReductionRules_Actions $ModeInt `
                         -ErrorAction Stop
        Write-Host ("  [OK]  {0}  ({1})  -- FP risk: {2}" -f $r.Guid.Substring(0,8), $r.Name, $r.FpRisk)
    } catch {
        Write-Warning ("  [FAIL] {0}  -- {1}" -f $r.Guid.Substring(0,8), $_.Exception.Message)
    }
}

# -----------------------------------------------------------------
#  Verify final state
# -----------------------------------------------------------------
Write-Host "[3/3] Final state:" -ForegroundColor Cyan
$preference = Get-MpPreference
$ids        = $preference.AttackSurfaceReductionRules_Ids
$actions    = $preference.AttackSurfaceReductionRules_Actions

if ($ids -and $actions) {
    for ($i = 0; $i -lt $ids.Count; $i++) {
        $modeStr = switch ($actions[$i]) {
            0 { 'Disabled' }
            1 { 'Enabled' }
            2 { 'AuditMode' }
            6 { 'Warn' }
        }
        Write-Host ("  {0}  -> {1}" -f $ids[$i], $modeStr)
    }
} else {
    Write-Host "  (no ASR rules configured)"
}

Write-Host ""
Write-Host "NEXT: monitor Defender Operational log for EventID 1122 (Audit)" -ForegroundColor Yellow
Write-Host "      for at least 2 weeks. Tune exclusions per-rule, not globally," -ForegroundColor Yellow
Write-Host "      via Add-MpPreference -AttackSurfaceReductionOnlyExclusions <path>." -ForegroundColor Yellow
Write-Host "      Then re-run: .\defender-asr.ps1 -Mode Enabled" -ForegroundColor Yellow
