/*
    Obfuscated JavaScript execution
    -------------------------------
    eval() fed by decoding helpers is typical of JScript droppers and
    malicious web injects.
*/
rule TB_Generic_Obfuscated_JavaScript_Eval
{
    meta:
        author      = "ThreatBytes"
        description = "Detects JavaScript that evaluates dynamically decoded content (eval with atob, unescape or fromCharCode)"
        date        = "2026-10-13"
        version     = "1.0"
        reference   = "https://attack.mitre.org/techniques/T1027/"
        mitre_attack = "T1059.007, T1027"
        severity    = "medium"

    strings:
        $e1 = /eval\s*\(\s*atob\s*\(/ nocase
        $e2 = /eval\s*\(\s*unescape\s*\(/ nocase
        $e3 = /eval\s*\(\s*String\.fromCharCode\s*\(/ nocase
        $e4 = /new\s+Function\s*\(\s*atob\s*\(/ nocase

    condition:
        filesize < 5MB and any of them
}
