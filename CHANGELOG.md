# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-13

### Added
- Eight starter rules:
  - `generic/`: UPX-packed PE, PowerShell download cradle, Base64-encoded PE in a script, Office macro with auto-exec, obfuscated JavaScript eval, Unix reverse shell
  - `test/`: EICAR test string
  - `examples/`: fictional FakeBytes loader
- Benign positive and negative test fixtures with `tests/expectations.yml`
- `scripts/test_rules.py` test runner (EICAR generated in memory at test time)
- GitHub Actions workflow to compile and test the rules on every push and pull request
- README, contributing guide, security policy, code of conduct, and issue/PR templates

[0.1.0]: https://github.com/THREATBYTES/YARA-Rule-Starter-Kit/releases/tag/v0.1.0
