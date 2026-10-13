/*
    Office VBA macro with auto-execution
    ------------------------------------
    Matches VBA source (extracted with olevba, or in a plain .bas/.vba file)
    containing an auto-exec entry point plus a suspicious capability.
*/
rule TB_Generic_Office_Macro_AutoExec
{
    meta:
        author      = "ThreatBytes"
        description = "Detects VBA macro code with an auto-exec trigger combined with execution or download capability"
        date        = "2026-10-13"
        version     = "1.0"
        reference   = "https://attack.mitre.org/techniques/T1137/"
        mitre_attack = "T1204.002, T1059.005, T1137"
        severity    = "medium"

    strings:
        // VBA markers
        $vba1 = "Attribute VB_Name" ascii wide nocase
        $vba2 = /\b(Private |Public )?Sub\s+\w+\s*\(/ nocase

        // Auto-execution entry points
        $auto1 = "AutoOpen" ascii wide nocase
        $auto2 = "Auto_Open" ascii wide nocase
        $auto3 = "Document_Open" ascii wide nocase
        $auto4 = "Workbook_Open" ascii wide nocase
        $auto5 = "AutoExec" ascii wide nocase
        $auto6 = "Document_Close" ascii wide nocase

        // Suspicious capabilities
        $sus1 = "Shell" ascii wide nocase
        $sus2 = "WScript.Shell" ascii wide nocase
        $sus3 = "CreateObject" ascii wide nocase
        $sus4 = "URLDownloadToFile" ascii wide nocase
        $sus5 = "MSXML2.XMLHTTP" ascii wide nocase
        $sus6 = "powershell" ascii wide nocase

    condition:
        filesize < 10MB and
        1 of ($vba*) and 1 of ($auto*) and 1 of ($sus*)
}
