/*
    UPX-packed Portable Executable
    ------------------------------
    UPX is a legitimate packer, but it is heavily abused to shrink and
    lightly obfuscate malware. Treat a match as a triage hint, not a verdict.
*/
rule TB_Generic_UPX_Packed_PE
{
    meta:
        author      = "ThreatBytes"
        description = "Detects a PE file packed with UPX (UPX0/UPX1 section names and UPX! marker)"
        date        = "2026-10-13"
        version     = "1.0"
        reference   = "https://upx.github.io/"
        mitre_attack = "T1027.002"
        severity    = "low"

    strings:
        $upx0   = "UPX0" ascii
        $upx1   = "UPX1" ascii
        $marker = "UPX!" ascii

    condition:
        uint16(0) == 0x5A4D and                        // "MZ" DOS header
        uint32(uint32(0x3C)) == 0x00004550 and         // "PE\0\0" signature
        filesize < 50MB and
        2 of them
}
