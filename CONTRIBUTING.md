# Contributing

## Development environment

Use Python 3.10 through 3.13 in an isolated environment. Install the local project with `python -m pip install .` and run the public suite with `python -m unittest discover -s tests/public -t . -v`.

## Test data

All public examples, fixtures, expected outputs, issue reports, and documentation snippets must be completely fictional. Do not copy confidential evaluation material, enterprise documents, proprietary calculations, credentials, or identifying metadata into a contribution.

Create the smallest reproducer that demonstrates the behavior. Preserve node and stream topology, provenance, review status, and deterministic expected results without imitating a real facility.

## Change discipline

Keep commits focused. Add a failing public test before changing behavior, implement the smallest correction, and run the full public suite. Changes to release files, package metadata, the canonical Skill, the adapter, or artifact membership require explicit review of their distribution impact.

## Release candidates

After the full Windows, Ubuntu, and Python matrix succeeds on `main`, one canonical Ubuntu job builds a uniquely named release candidate. Release authorization binds the candidate artifact name, its manifest digest, the source commit, the CI run, and every published asset digest.

The release workflow only downloads and verifies that approved candidate; it never rebuilds release assets. Contributors must not hand-edit, replace, rename, or repackage candidate files. Any candidate change requires a new successful main CI run and a new authorization.
## Review expectations

Reviewers check deterministic behavior, compatibility with Python 3.10 through 3.13, fictional-data boundaries, archive safety, documentation clarity, and whether technician authority remains explicit. A passing test suite does not override a security or confidentiality concern.

## Contribution license

By submitting a contribution, you agree that it may be distributed under Apache-2.0 and that you have the right to provide it under those terms. Do not submit material whose license or confidentiality terms are incompatible with this project.
