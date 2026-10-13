# Contributing

Thank you for helping improve the YARA Rule Starter Kit! Contributions of new rules, better fixtures, fixes for false positives and documentation are all welcome.

## Ground rules

- **No live malware, ever.** Fixtures must be small, crafted, benign files. Reference real samples by hash only.
- Be kind and constructive; see the [Code of Conduct](CODE_OF_CONDUCT.md).
- Use British English in documentation and rule descriptions.

## Workflow

1. Fork the repository and create a branch: `git checkout -b rule/my-new-rule`.
2. Add your rule under the most suitable folder in `rules/`.
3. Add at least one **positive** fixture (should match) and one **negative** fixture (should not match) under `tests/fixtures/`.
4. Map each fixture to its expected rules in `tests/expectations.yml`.
5. Run the tests:
   ```bash
   pip install -r requirements.txt
   python scripts/test_rules.py
   ```
6. Add an entry to `CHANGELOG.md` under *Unreleased*.
7. Open a pull request and complete the checklist.

## Rule requirements

- Name: `TB_<Category>_<Descriptive_Name>` (e.g. `TB_Generic_UPX_Packed_PE`).
- A comment block above the rule explaining what it detects and why.
- A complete `meta` section: `author`, `description`, `date` (YYYY-MM-DD), `version`, `reference`, `mitre_attack` (where relevant) and `severity`.
- Bound the scan with `filesize` and use cheap checks (magic bytes) first.
- Avoid single, very short or very common strings that cause false positives.

See the *Style guide* section in the [README](README.md#style-guide) for more detail.
