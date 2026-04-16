---
description: Cut a new CertMonitor release. Bumps versions, reformats the CHANGELOG, opens the develop→main PR, and creates a draft GitHub Release — stopping just before publish so you can review.
---

# Release workflow for CertMonitor

You are cutting a new release of CertMonitor. The user will provide the version
number (e.g. "0.4.0") as $ARGUMENTS, or you should ask for it if not provided.

## Steps

1. **Validate preconditions**
   - Confirm you are on the `develop` branch and it is clean (`git status`).
   - Confirm `develop` is up to date with `origin/develop` (`git pull`).
   - Confirm `make test` passes (full local CI).
   - Read `CHANGELOG.md` and confirm the `[Unreleased]` section has real content (not just "TBD").
   - If any precondition fails, stop and tell the user what needs to be fixed.

2. **Bump versions**
   - Update `version` in `pyproject.toml` to the new version.
   - Update `version` in `Cargo.toml` to the new version.
   - Run `make develop` to rebuild with the new version (updates `Cargo.lock`).

3. **Reformat CHANGELOG.md**
   - Rename the `## [Unreleased]` header to `## [X.Y.Z] - YYYY-MM-DD` using today's date.
   - Add a new empty `## [Unreleased]` section above it with `### Added`, `### Changed`, `### Fixed` stubs (all "- TBD").
   - Convert the release section's headers from plain format to emoji format:
     - `### Added` → `## ✨ Added`
     - `### Changed` → `## 🔄 Changed`
     - `### Fixed` → `## 🛠️ Fixed`
     - `### Deprecated` → `## ⚠️ Deprecated` (if present)
     - `### Security` → `## 🔒 Security` (if present)
   - Add the release title line at the top of the section: `# 📦 CertMonitor vX.Y.Z – <short tagline>`
   - Add the metadata block below it:
     ```
     **Release Date:** <Month Day, Year>
     **Repository:** [bradh11/certmonitor](https://github.com/bradh11/certmonitor)

     ---

     ## 🚀 Overview

     <Write a 2-3 sentence overview paragraph summarizing the release.>

     ---
     ```
   - Add these standard footer sections at the end of the release (before the next `## [` header):
     ```
     ---

     ## 📚 Documentation

     Comprehensive documentation is available at [certmonitor.readthedocs.io](https://certmonitor.readthedocs.io/).

     ---

     ## 🐍 Python Compatibility

     Tested with Python 3.8 through 3.13 with <coverage>% code coverage across all supported versions.

     ---

     ## 📝 License

     This project is licensed under the MIT License. See the [LICENSE](https://github.com/bradh11/certmonitor/blob/main/LICENSE) file for details.

     **Full Changelog**: https://github.com/bradh11/certmonitor/compare/vPREVIOUS...vNEW
     ```
   - Add `---` dividers between each emoji-header section for visual separation.
   - The content under each section stays as-is from the Unreleased draft — just the headers and structure change.

4. **Run final CI**
   - Run `make test` to verify everything is clean at the new version.

5. **Commit and push**
   - Stage `pyproject.toml`, `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, and `MODULARIZATION_REPORT.md`.
   - Commit with message: `Release X.Y.Z`
   - Push to `origin/develop`.

6. **Open the release PR**
   - `gh pr create --base main --head develop --title "Release X.Y.Z"` with a body summarizing the highlights from the changelog.

7. **Wait for CI on the PR**
   - Watch CI with `gh pr checks <number> --watch`.
   - If CI fails, fix and push before proceeding.

8. **Create a draft GitHub Release**
   - Extract the release notes from CHANGELOG.md (everything between `## [X.Y.Z]` and the next `## [`).
   - Create the draft: `gh release create vX.Y.Z --draft --target main --title "Release vX.Y.Z" --notes "<extracted notes>"`.

9. **Tell the user what's left**
   - Print the PR URL and draft release URL.
   - Tell them to:
     1. Merge the PR on GitHub.
     2. Tag main: `git checkout main && git pull && git tag vX.Y.Z && git push origin vX.Y.Z`
     3. Publish the draft release on GitHub (the tag push triggers `release.yml` which will update the release with CHANGELOG content, but since the format now matches, this is fine).
     4. Sync develop: `git checkout develop && git merge main && git push`

## Important notes

- Do NOT push tags yourself. The user tags and publishes.
- Do NOT merge the PR yourself. The user merges.
- Do NOT use `generate_release_notes: true` — CHANGELOG.md is authoritative.
- The CHANGELOG emoji format must match exactly so `release.yml`'s awk extraction produces clean GitHub Release notes.
- Do not add any AI attribution or AI-giveaway phrasing to commits, PRs, or release notes.
