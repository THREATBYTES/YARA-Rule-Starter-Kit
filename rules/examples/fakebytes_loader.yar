/*
    FakeBytes Loader (FICTIONAL)
    ----------------------------
    FakeBytes is an invented malware family used throughout ThreatBytes
    training material, including THREATBYTES/Malware-Analysis-Report-Template.
    The indicators below are made up and use reserved example domains/IPs.
    Use this rule as a worked example of a family-specific detection.
*/
rule TB_Example_FakeBytes_Loader
{
    meta:
        author      = "ThreatBytes"
        description = "Example family rule for the fictional FakeBytes loader (training use only)"
        date        = "2026-10-13"
        version     = "1.0"
        reference   = "https://github.com/THREATBYTES/Malware-Analysis-Report-Template"
        mitre_attack = "T1071.001, T1105, T1547.001"
        malware_family = "FakeBytes (fictional)"
        severity    = "high"

    strings:
        $mutex   = "Global\\FB_Loader_Mutex_7a3c" ascii wide
        $ua      = "FakeBytesLoader/1.0" ascii wide
        $c2_1    = "fakebytes-c2.example" ascii wide
        $c2_2    = "198.51.100.23" ascii wide              // RFC 5737 documentation range
        $runkey  = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\FBUpdater" ascii wide nocase
        $cfg     = { 46 42 43 46 47 00 01 }                // "FBCFG" config blob magic + version 1

    condition:
        filesize < 2MB and
        ($mutex or $cfg) and 2 of ($ua, $c2_*, $runkey)
}
