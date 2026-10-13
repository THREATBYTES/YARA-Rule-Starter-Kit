/*
    EICAR anti-malware test file
    ----------------------------
    A harmless, industry-standard string used to test that scanners work.
    The pattern is stored as hex so this rule file itself is not flagged.
*/
rule TB_Test_EICAR
{
    meta:
        author      = "ThreatBytes"
        description = "Detects the EICAR anti-malware test string (harmless; for pipeline testing)"
        date        = "2026-10-13"
        version     = "1.0"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
        severity    = "informational"

    strings:
        // "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR" (first 33 bytes, hex)
        $head = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 }
        // "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $tail = { 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }

    condition:
        $head at 0 and $tail and filesize < 128
}
