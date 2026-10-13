/*
    Base64-encoded PE embedded in a script
    --------------------------------------
    "TVqQAAMAAAAEAAAA" is the Base64 of a standard MZ header. Droppers often
    carry an executable this way and decode it at runtime.
*/
rule TB_Generic_Base64_PE_In_Script
{
    meta:
        author      = "ThreatBytes"
        description = "Detects a Base64-encoded Windows PE header inside a non-PE file (script, document, text)"
        date        = "2026-10-13"
        version     = "1.0"
        reference   = "https://attack.mitre.org/techniques/T1027/"
        mitre_attack = "T1027, T1140"
        severity    = "medium"

    strings:
        $mz1 = "TVqQAAMAAAAEAAAA" ascii wide
        $mz2 = "TVpQAAIAAAAEAA8A" ascii wide        // Borland/Delphi-style header
        $mz3 = "TVoAAAAAAAAAAAAA" ascii wide
        $dos = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGU" ascii wide  // "This program cannot be run in DOS mode"

    condition:
        uint16(0) != 0x5A4D and          // the file itself is not a PE
        filesize < 20MB and
        any of them
}
