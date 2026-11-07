# Security policy

Trail Evidence verifies hash chains and signatures, so a flaw in hashing,
canonicalisation, signature checking or verdict logic can make a broken
journal look valid. Such reports are handled privately first.

## Reporting a vulnerability

Please do not report a suspected vulnerability in a public issue, pull
request or discussion.

Report it privately through GitHub instead: open the **Security** tab of this
repository and choose **Report a vulnerability**, or go straight to
<https://github.com/RainerGewalt/trail-evidence/security/advisories/new>. Only you
and the maintainer can see the report and the conversation about it.

Include what you can safely share: the affected version or commit, how to
reproduce it, and the impact as you understand it. Never include real
credentials, private keys or production data.

Most useful are reports where a verifier (Go, Python, browser or the GitHub
Action) reports `valid` for a journal that should be `invalid` or
`incomplete`, or where two verifiers disagree on the same input. The key
under `testdata/keys/` is a published test key (RFC 8032 test vector 1) and
not a finding.

## What happens after you report

- Reports are handled confidentially. Nothing from a report is copied into a
  public issue. If a report is confirmed, it becomes public as a GitHub
  security advisory together with the fix, crediting you if you want that.
- Reports are read and answered on a best-effort basis by a single
  maintainer. There is no guaranteed response or fix time, and none is
  implied by this document.
- A report that includes a reproduction is acted on before one that does not.
- Fixes ship in the next release. There is no backport to older releases.
