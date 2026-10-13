# YARA Rule Starter Kit

[![YARA CI](https://github.com/THREATBYTES/YARA-Rule-Starter-Kit/actions/workflows/yara-ci.yml/badge.svg)](https://github.com/THREATBYTES/YARA-Rule-Starter-Kit/actions/workflows/yara-ci.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

A small, well-commented collection of YARA rules with **safe test fixtures** and a **CI pipeline**, built by [ThreatBytes](https://www.threatbytes.dev) to help analysts and students learn to write, test and maintain detections.

## What is YARA?

[YARA](https://virustotal.github.io/yara/) is the "pattern-matching Swiss Army knife" for malware researchers. A YARA rule describes a family or behaviour using text strings, byte patterns, regular expressions and logical conditions; the YARA engine then scans files or memory and reports which rules match. It is used in incident response, threat hunting, sandboxing and email/file scanning.

## Quick start

```bash
git clone https://github.com/THREATBYTES/YARA-Rule-Starter-Kit.git
cd YARA-Rule-Starter-Kit
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Compile all rules and run them against the test fixtures
python scripts/test_rules.py
```

To scan your own files with the YARA command-line tool:

```bash
yara -r rules/generic/ /path/to/suspect/files
```

## Rule index

| Rule | File | Detects | MITRE ATT&CK |
|------|------|---------|--------------|
| `TB_Generic_UPX_Packed_PE` | [rules/generic/upx_packed_pe.yar](rules/generic/upx_packed_pe.yar) | PE files packed with UPX | T1027.002 |
| `TB_Generic_PowerShell_Download_Cradle` | [rules/generic/powershell_download_cradle.yar](rules/generic/powershell_download_cradle.yar) | PowerShell download-and-execute one-liners | T1059.001, T1105 |
| `TB_Generic_Base64_PE_In_Script` | [rules/generic/base64_pe_in_script.yar](rules/generic/base64_pe_in_script.yar) | Base64-encoded PE header inside a non-PE file | T1027, T1140 |
| `TB_Generic_Office_Macro_AutoExec` | [rules/generic/office_macro_autoexec.yar](rules/generic/office_macro_autoexec.yar) | VBA macros with auto-exec plus execution/download capability | T1204.002, T1059.005, T1137 |
| `TB_Generic_Obfuscated_JavaScript_Eval` | [rules/generic/obfuscated_javascript.yar](rules/generic/obfuscated_javascript.yar) | `eval()` of decoded content (atob, unescape, fromCharCode) | T1059.007, T1027 |
| `TB_Generic_Unix_Reverse_Shell` | [rules/generic/linux_reverse_shell.yar](rules/generic/linux_reverse_shell.yar) | Bash `/dev/tcp`, `nc -e` and `mkfifo` reverse shells | T1059.004 |
| `TB_Test_EICAR` | [rules/test/eicar.yar](rules/test/eicar.yar) | The harmless EICAR anti-malware test string | n/a |
| `TB_Example_FakeBytes_Loader` | [rules/examples/fakebytes_loader.yar](rules/examples/fakebytes_loader.yar) | The **fictional** FakeBytes loader used in ThreatBytes training | T1071.001, T1105, T1547.001 |

## Repository layout

```
rules/
  generic/     Behaviour and technique rules
  test/        Pipeline sanity checks (EICAR)
  examples/    Worked family rules for fictional malware
tests/
  fixtures/positive/   Crafted files that SHOULD match
  fixtures/negative/   Clean files that must NOT match
  expectations.yml     Fixture -> expected rules
scripts/test_rules.py  Compiles rules and checks results
```

## Writing and testing a new rule

1. **Create the rule** in the right folder, e.g. `rules/generic/my_rule.yar`, starting from this template:

   ```yara
   /*
       Short title
       -----------
       What it detects, why it matters and known false positives.
   */
   rule TB_Generic_My_Rule
   {
       meta:
           author       = "ThreatBytes"
           description  = "One sentence describing the detection"
           date         = "2026-10-13"
           version      = "1.0"
           reference    = "https://attack.mitre.org/techniques/T0000/"
           mitre_attack = "T0000"
           severity     = "medium"

       strings:
           $a = "something distinctive" ascii wide nocase

       condition:
           filesize < 5MB and $a
   }
   ```

2. **Add fixtures**: one or more small, benign files in `tests/fixtures/positive/` that should match, and at least one realistic clean file in `tests/fixtures/negative/` that should not.
3. **Record expectations** in `tests/expectations.yml`:

   ```yaml
   fixtures:
     positive/my_rule_hit.txt: [TB_Generic_My_Rule]
     negative/my_rule_clean.txt: []
   ```

4. **Run the tests**: `python scripts/test_rules.py`. The script fails if any rule does not compile, if a fixture matches too many or too few rules, or if a fixture file is not listed in `expectations.yml`.
5. **Open a pull request**; the CI workflow runs the same checks automatically.

## Style guide

- **Naming:** `TB_<Category>_<Descriptive_Name>` in Pascal_Snake_Case; one rule per concept.
- **Comment block** above every rule explaining intent and known false positives.
- **Meta:** always include `author`, `description`, `date` (ISO 8601), `version`, `reference`, `severity`, and `mitre_attack` where a technique applies.
- **Performance:** check cheap conditions first (magic bytes such as `uint16(0) == 0x5A4D`), always bound with `filesize`, and avoid unanchored regular expressions with leading wildcards.
- **Precision:** combine indicators (`1 of ($download*) and 1 of ($exec*)`) rather than relying on one common string.
- **Strings:** use descriptive identifiers (`$mutex`, `$ua`), and add `wide` / `nocase` deliberately, not by habit.
- **Language:** British English in descriptions and documentation.

## Safety note

**This repository contains no live malware.** Every fixture is a small, hand-crafted, benign text or byte file that only *imitates* the patterns the rules look for: URLs use reserved `.example`/`.invalid` domains and RFC 5737 documentation IP addresses, the PE fixtures are header-only stubs that cannot run, and the FakeBytes family is entirely fictional.

The **EICAR** test string is not stored anywhere in the repository. The rule holds it as hex bytes, and `scripts/test_rules.py` assembles it in memory at test time (from two halves, one reversed) so that cloning or scanning this repository will not trip antivirus software.

Never commit real samples. Reference them by hash instead.

## Part of ThreatBytes

This kit is part of the [ThreatBytes](https://www.threatbytes.dev) collection of free security learning resources. The fictional FakeBytes loader also appears in the sibling project [THREATBYTES/Malware-Analysis-Report-Template](https://github.com/THREATBYTES/Malware-Analysis-Report-Template), so you can follow one example from analysis report to detection rule.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [SECURITY.md](SECURITY.md).

## Licence

Released under the [MIT Licence](LICENSE). Copyright (c) 2026 ThreatBytes.
