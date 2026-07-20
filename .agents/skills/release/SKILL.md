---
name: release
description: Prepare and publish a Postkit release by validating a requested semantic version, drafting release notes, updating the SDK version and lockfile, running checks, committing, creating an annotated tag, and pushing the commit and tag. Use when the user asks to release or publish a specific Postkit version.
---

# Release Postkit

Require an explicit release version such as `0.10.0`. If none is provided, ask for it before changing anything. Treat the version as applying to both the SQL bundles and Python SDK; `sdk/pyproject.toml` stores the canonical version, while the SQL files have no version field.

Run every command from the repository root. Follow the release-note conventions in `AGENTS.md`. Do not create a changelog.

## Preflight

Stop without making changes and report the failed condition unless all checks pass:

1. Validate that the requested version is SemVer and does not start with `v`.
2. Verify `git status --short` is empty.
3. Verify `git branch --show-current` returns `main`.
4. Run `git fetch origin main`, then verify `git diff --quiet main origin/main`. If they differ, tell the user to pull first.
5. Verify `git tag -l "v<version>"` is empty.
6. Verify `sdk/pyproject.toml` has a static `version` under `[project]` and does not list `version` under `dynamic`.

## Draft and approve release notes

1. Find the previous tag with `git describe --tags --abbrev=0`.
2. Inspect every commit since that tag, including commit bodies and stats. Do not infer migration details that the commit body omits.
3. Draft notes using the conventions in `AGENTS.md`: one plain sentence per change ending with its short commit hash; group entries under breaking, added, and fixed as applicable; put breaking first; end with the compare link to the previous tag.
4. Show the complete draft to the user and stop for explicit approval. Do not modify version files, commit, tag, or push before approval.
5. After approval, save the exact notes to a temporary file created with `mktemp`.

## Publish

1. Update only the `[project].version` field in `sdk/pyproject.toml`.
2. Run `make lint`.
3. Run `make test`.
4. Run `uv lock --directory sdk`.
5. If lint, tests, or lock generation fails, restore only `sdk/pyproject.toml` and `sdk/uv.lock` to their pre-release contents and stop. Do not commit or tag.
6. Confirm the diff contains only the intended version changes.
7. Stage only `sdk/pyproject.toml` and `sdk/uv.lock`.
8. Commit as `release: v<version>` with no co-author trailers.
9. Create the annotated tag with `git tag -a "v<version>" --cleanup=verbatim -F <notes-file>`. Keep `--cleanup=verbatim` so Markdown headings beginning with `#` remain in the tag message.
10. Push separately: first `git push origin main`, then `git push origin "v<version>"`.
11. Report the commit, tag, and push results. Remove the temporary notes file.

Pushing the tag triggers `.github/workflows/release.yml`, which publishes `dist/*.sql` to a GitHub Release using the annotated tag message and publishes the SDK to PyPI. PyPI requires the repository's one-time trusted-publisher setup.
