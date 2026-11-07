# Releasing

A release is one tag `vX.Y.Z` on `main`. The tag names the format draft, the
Go CLI, the Python package and the GitHub Action at once; they share one
version number.

## Before the tag

1. `CHANGELOG.md`: move the entries under "Unreleased" to a section
   `## X.Y.Z - YYYY-MM-DD`.
2. `python/pyproject.toml` and `python/trail_evidence/__init__.py`: set
   `version` and `__version__` to `X.Y.Z`; `devVersion` in
   `go/cmd/trail-evidence/main.go` names the next version after the tag
   (`X.Y+1.0-dev`). The release workflow fails when the tag and
   `pyproject.toml` disagree. Release binaries get their version from the
   tag (`-ldflags "-X main.version={{ .Version }}"` in `.goreleaser.yaml`).
3. Run the full check locally (see `CONTRIBUTING.md`), plus
   `goreleaser check` and, if GoReleaser is installed,
   `goreleaser release --snapshot --clean` to see the archives in `dist/`.
4. Run the first-use check from a fresh clone of the release commit:
   `scripts/first-use.sh` (`docs/TESTING.md`, L5). No tag without a pass.

## Tag

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

`.github/workflows/release.yml` then:

- runs `go test ./...` and the generated-files check;
- runs GoReleaser (`.goreleaser.yaml`): binaries for Linux, macOS and
  Windows on amd64 and arm64, one archive per target with `LICENSE` and
  `SPEC.md`, and `checksums.txt` (SHA-256), attached to the GitHub release;
- pushes the Go module tag `go/vX.Y.Z`. The module lives in `go/`, so
  `go install github.com/RainerGewalt/trail-evidence/go/cmd/trail-evidence@vX.Y.Z`
  needs that prefixed tag. Without it `@latest` still works but resolves to
  a pseudo-version of `main`;
- builds the Python sdist and wheel, installs the wheel, runs
  `trail-evidence-py verify` on an example journal and keeps `python/dist/`
  as the workflow artifact `python-dist-vX.Y.Z`;
- uploads that artifact to PyPI through trusted publishing (job `pypi`,
  below). A failed upload fails the job, so a green release run means the
  package is on PyPI.

The GitHub Action needs no extra step: `uses: RainerGewalt/trail-evidence@vX.Y.Z`
resolves the same tag and installs the matching CLI.

## After the tag

Run `RELEASE=X.Y.Z scripts/first-use.sh`. It checks what was published: the
tag, the release archive against `checksums.txt`, `go install …@vX.Y.Z`,
`pip install trail-evidence==X.Y.Z` and the browser verifier on GitHub
Pages. If it fails, a patch release follows.

## PyPI (trusted publishing)

The job `pypi` in `.github/workflows/release.yml` uploads the sdist and wheel
with `pypa/gh-action-pypi-publish`. There is no API token: the job runs in
the GitHub environment `pypi` with `id-token: write`, and PyPI accepts the
upload because it trusts this repository's workflow `release.yml` in that
environment.

### One-time setup

The project `trail-evidence` does not exist on PyPI until its first upload,
so the trust is registered as a **pending publisher**:

1. Sign in to <https://pypi.org> with the account that is to own the
   project, and open "Your account" → "Publishing"
   (<https://pypi.org/manage/account/publishing/>).
2. Under "Add a new pending publisher", choose GitHub and enter exactly:

   | Field | Value |
   |---|---|
   | PyPI Project Name | `trail-evidence` |
   | Owner | `RainerGewalt` |
   | Repository name | `trail-evidence` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

3. Optional, on GitHub: Settings → Environments → `pypi`. The workflow
   creates the environment on its first run if it does not exist; adding
   required reviewers there makes every upload wait for an approval.

The first successful upload creates the project, and the pending publisher
becomes a regular trusted publisher of it. A pending publisher does not
reserve the name: until the first upload, another account could register a
project called `trail-evidence`, so the setup is best done shortly before
the first release that is to reach PyPI.

### Status and fallback

The publisher was registered on 2026-11-03; 0.2.0 was the first upload. A
failed upload now fails the release job, so a green release run means the
package is on PyPI. If an upload fails, fix the cause and re-run only the
PyPI job; the GitHub release, the binaries and the Go module tag are not
affected by a re-run. Manual fallback, only if trusted publishing is
unavailable:

```bash
gh run download --repo RainerGewalt/trail-evidence -n python-dist-vX.Y.Z -D dist-py
python3 -m pip install --upgrade twine
python3 -m twine check dist-py/*
python3 -m twine upload dist-py/*        # asks for a project-scoped PyPI API token
```

Do not store a token in the repository. Check the result in a fresh virtual
environment:

```bash
python3 -m venv /tmp/te && /tmp/te/bin/pip install trail-evidence==X.Y.Z
/tmp/te/bin/trail-evidence-py verify examples/transfer-worker.jsonl
/tmp/te/bin/trail-evidence-py profiles
```

## After the release

- `go install github.com/RainerGewalt/trail-evidence/go/cmd/trail-evidence@vX.Y.Z`
  and `trail-evidence version` print `X.Y.Z`.
- The `self-test` workflow is green on `main`.
- GitHub Marketplace listing of the Action is a manual step on the release
  page ("Publish this Action to the GitHub Marketplace"); it is optional.
