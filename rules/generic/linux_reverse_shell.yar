/*
    Unix reverse shell one-liners
    -----------------------------
    Common patterns used to call back to an attacker-controlled listener.
*/
rule TB_Generic_Unix_Reverse_Shell
{
    meta:
        author      = "ThreatBytes"
        description = "Detects common Unix reverse shell one-liners (bash /dev/tcp, nc -e, mkfifo pipes)"
        date        = "2026-10-13"
        version     = "1.0"
        reference   = "https://attack.mitre.org/techniques/T1059/004/"
        mitre_attack = "T1059.004"
        severity    = "high"

    strings:
        $r1 = /bash\s+-i\s*>&\s*\/dev\/tcp\/[\w.\-]+\/\d{1,5}/
        $r2 = /\bnc(at)?\s+(-\w+\s+)*-e\s+\/bin\/(ba)?sh/
        $r3 = /mkfifo\s+\/tmp\/\w+;\s*cat\s+\/tmp\/\w+\s*\|\s*\/bin\/(ba)?sh/
        $r4 = /0<&\d+;\s*exec\s+\d+<>\/dev\/tcp\//

    condition:
        filesize < 5MB and any of them
}
