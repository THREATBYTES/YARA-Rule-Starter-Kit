/*
    PowerShell download cradle
    --------------------------
    Classic one-liners that fetch remote content and execute it in memory,
    e.g. IEX (New-Object Net.WebClient).DownloadString('http://...').
*/
rule TB_Generic_PowerShell_Download_Cradle
{
    meta:
        author      = "ThreatBytes"
        description = "Detects PowerShell download-and-execute cradles in scripts or command lines"
        date        = "2026-10-13"
        version     = "1.0"
        reference   = "https://attack.mitre.org/techniques/T1059/001/"
        mitre_attack = "T1059.001, T1105"
        severity    = "medium"

    strings:
        // Download primitives
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadData" ascii wide nocase
        $dl3 = "DownloadFile" ascii wide nocase
        $dl4 = "Invoke-WebRequest" ascii wide nocase
        $dl5 = "Net.WebClient" ascii wide nocase
        $dl6 = "Start-BitsTransfer" ascii wide nocase
        $dl7 = /\biwr\s+(-Uri\s+)?['"]?https?:\/\//i

        // Execution primitives
        $ex1 = "Invoke-Expression" ascii wide nocase
        $ex2 = /\bIEX\b/i
        $ex3 = /\|\s*iex\b/i

    condition:
        filesize < 5MB and
        1 of ($dl*) and 1 of ($ex*)
}
