# Releasing

A release is one tag `vX.Y.Z` on `main`. The tag names the format draft, the
Go CLI, the Python package and the GitHub Action at once; they share one
version number.

## Before the tag

1. `CHANGELOG.md`: move the entries under "Unreleased" to a section
   `## X.Y.Z - YYYY-MM-DD`.
2. `python/pyproject.toml` and `python/trail_evidence/__init__.py`: set
   `version` and `__version__` to `X.Y.Z`. The release workflow fails when
   the tag and `pyproject.toml` disagree.
3. Run the full check locally (see `CONTRIBUTING.md`), plus
   `goreleaser check` and, if GoReleaser is installed,
   `goreleaser release --snapshot --clean` to see the archives in `dist/`.

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
  as the workflow artifact `python-dist-vX.Y.Z`.

The GitHub Action needs no extra step: `uses: RainerGewalt/trail-evidence@vX.Y.Z`
resolves the same tag and installs the matching CLI.

## PyPI (manual)

The workflow does not upload to PyPI. After the release workflow has
finished:

```bash
gh run download --repo RainerGewalt/trail-evidence -n python-dist-vX.Y.Z -D dist-py
python3 -m pip install --upgrade twine
python3 -m twine check dist-py/*
python3 -m twine upload dist-py/*        # asks for the PyPI API token
```

Use a project-scoped API token and do not store it in the repository. Check
the result in a fresh virtual environment:

```bash
python3 -m venv /tmp/te && /tmp/te/bin/pip install trail-evidence==X.Y.Z
/tmp/te/bin/trail-evidence-py verify examples/transfer-worker.jsonl
```

## After the release

- `go install github.com/RainerGewalt/trail-evidence/go/cmd/trail-evidence@vX.Y.Z`
  and `trail-evidence version` print `X.Y.Z`.
- The `self-test` workflow is green on `main`.
- GitHub Marketplace listing of the Action is a manual step on the release
  page ("Publish this Action to the GitHub Marketplace"); it is optional.
