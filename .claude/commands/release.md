---
description: Bump the version, run checks, commit, tag, and push a release
allowed-tools: Bash(git *), Bash(make *), Bash(uv *), Bash(grep *), Read, Edit, Write
---

Release version $ARGUMENTS.

This is the version for the whole release: the tag `v$ARGUMENTS` versions both the SQL
bundles and the SDK. `sdk/pyproject.toml` is just where the canonical number is stored; the
SQL files carry no version field. The lockfile is `sdk/uv.lock`. Lint and tests run through
the Makefile from the repo root; `make test` brings up Postgres in Docker.

Pre-flight checks (stop and report if any fail):
1. Working tree is clean: `git status --short` must produce no output
2. Current branch is main: `git branch --show-current` must output `main`
3. Local main is up to date: `git fetch origin main && git diff --quiet main origin/main` -- if it fails, tell the user to pull first
4. Tag doesn't exist: `git tag -l "v$ARGUMENTS"` must produce no output
5. `$ARGUMENTS` looks like a valid semver (e.g. 0.2.0, 1.0.0)
6. `sdk/pyproject.toml` has a static `version` under `[project]`, not listed in `dynamic`

Steps:
1. Write the release notes. Find the previous tag with `git describe --tags --abbrev=0`, read the commits since it with `git log --stat <prev>..HEAD`, and draft the notes following the release-notes conventions in AGENTS.md: one line per change, each a single plain sentence ending with the short commit hash, grouped under breaking, added, and fixed headings as applicable, breaking first, ending with the compare link to the previous tag. Show the draft to the user and get their go-ahead before continuing, then save it to a temp file for the tag step.
2. Update the `version` field in `sdk/pyproject.toml` to `$ARGUMENTS`
3. Run `make lint` to verify linting passes -- if it fails, run `git checkout sdk/pyproject.toml` to revert and stop
4. Run `make test` to verify tests pass -- if they fail, run `git checkout sdk/pyproject.toml` to revert and stop
5. Run `uv lock --directory sdk` to update the lockfile
6. Stage only the version files: `git add sdk/pyproject.toml sdk/uv.lock`
7. Commit with message `release: v$ARGUMENTS` (no Co-Authored-By trailers)
8. Create the annotated tag with the approved notes as its message: `git tag -a "v$ARGUMENTS" -F <notes-file>`
9. Push the commit and tag separately: `git push origin main && git push origin "v$ARGUMENTS"`

If lint or tests fail, revert with `git checkout sdk/pyproject.toml` and stop. Do not commit or tag.

Note: pushing the tag triggers `.github/workflows/release.yml`, which publishes the SQL
bundles (`dist/*.sql`) to a GitHub Release using the tag message as the release notes, and
the SDK to PyPI. The GitHub Release works out of the box; PyPI publishing requires a
one-time PyPI trusted-publisher setup for this repo.
