# Releasing API Tester

Everything is done with one script: **`tools/Release.ps1`** (Windows PowerShell 5.1 or PowerShell 7, needs `git`).

## What the in-app updater needs

Help -> About -> *Check for updates* (and a silent daily check at start-up) reads
`https://api.github.com/repos/imumeshk/API-Tester/releases/latest`, so a release is only offered when:

- it is **published** - not a draft and not a pre-release;
- its **tag** is `vX.Y.Z` and higher than `$script:AppVersion` of the running copy;
- it has an asset named exactly **`API-Tester.ps1`** (otherwise the releases page is opened instead);
- `API-Tester.ps1.sha256` is attached - the download is rejected when it does not match;
- the repository is **public** (the updater sends no token).

`tools/Release.ps1 Publish` and the Release workflow take care of all of this; `tools/Release.ps1 Verify` checks it.

## One-time setup

```powershell
.\tools\Release.ps1 Init        # .gitignore entries + stop tracking user data and docs\internal
git commit -m "Stop tracking user data"
```

On GitHub: **Settings -> Actions -> General -> Workflow permissions -> Read and write permissions** (lets the
Release workflow create releases).

A token is only needed for actions that change releases through the API (`UpdateNotes`, `UploadAssets`, `Delete`,
`Publish -Mode Api`). Create a fine-grained token at https://github.com/settings/personal-access-tokens with access to
the repository and **Contents: Read and write**, then for the current session:

```powershell
$env:GITHUB_TOKEN = '<token>'      # or sign in once with the GitHub CLI: gh auth login
```

## Everyday flow

```powershell
# 1. Record changes as you work (goes under "## [Unreleased]" in CHANGELOG.md)
.\tools\Release.ps1 AddChange -Type Added   -Message "Export history to HAR."
.\tools\Release.ps1 AddChange -Type Fixed   -Message "Proxy settings are kept after an update."

# 2. See where things stand
.\tools\Release.ps1 Status

# 3. Release (patch / minor / major, or an explicit -Version)
.\tools\Release.ps1 Publish -Bump Patch
```

`Publish` does, in order:

1. checks you are on `main`, up to date with `origin`, and that the tag does not exist yet;
2. sets `$script:AppVersion` in `src/Config/Constants.ps1`;
3. moves the `[Unreleased]` notes into `## [x.y.z] - date` and updates the compare links in `CHANGELOG.md`;
4. writes `docs/releases/vX.Y.Z.md` from that section (a hand-written file with that name is kept);
5. runs `Build.ps1` (syntax check, `dist/API-Tester.ps1.sha256`) and adds the checksum to the notes;
6. refuses to commit user data, then commits `Release vX.Y.Z`, tags `vX.Y.Z` and pushes branch and tag;
7. waits for the **Release** workflow to publish the release with `API-Tester.ps1` and `API-Tester.ps1.sha256`
   (or, with `-Mode Api`, creates the release and uploads the assets itself);
8. verifies what the updater sees (latest release, tag = version inside the script, checksum, script parses).

Add `-DryRun` to any command to see what it would do without changing anything.

## Command reference

| Command | What it does |
|---|---|
| `Status` | Local version, branch, uncommitted changes, ahead/behind, tracked user data, `[Unreleased]` entries, latest GitHub release. |
| `Init` | Adds missing `.gitignore` entries and untracks user data, `docs/internal` and backup files (files stay on disk). |
| `AddChange -Type <Added\|Changed\|Deprecated\|Removed\|Fixed\|Security> -Message "..."` | Adds a CHANGELOG entry under `[Unreleased]`, keeping the sections in the standard order. |
| `NextVersion -Bump <Major\|Minor\|Patch> [-PreRelease beta.1]` | Shows the next version number. |
| `Notes [-Version x.y.z] [-Force]` | Creates `docs/releases/vX.Y.Z.md` from the CHANGELOG (`-Force` overwrites a hand-written file). |
| `Prepare [-Version x.y.z \| -Bump ...]` | Steps 2-5 above, nothing is committed - review, then `Publish`. |
| `Publish [-Version x.y.z \| -Bump ...] [-Mode Auto\|Workflow\|Api] [-Draft] [-NoWait]` | The complete release (see above). Versions with a hyphen (`3.1.0-beta.1`) become pre-releases, which the updater ignores. `-Draft` needs `-Mode Api`. |
| `UpdateNotes [-Version x.y.z] [-NotesFile path]` | Replaces the text of an existing release with its notes file. |
| `UploadAssets [-Version x.y.z] [-SkipBuild]` | Rebuilds and re-uploads `API-Tester.ps1` and `.sha256` to an existing release (old assets are replaced). |
| `Verify [-Version x.y.z]` | Checks the latest release exactly like the updater does; exit code 1 when something is wrong. |
| `List` | Lists releases with their state (latest / published / pre-release / draft) and assets. |
| `Delete -Version x.y.z [-DeleteTag] [-Force]` | Deletes a release (and the tag with `-DeleteTag`) after typing the tag to confirm. |

Common options: `-Repository owner/name` (default `$script:AppGitHubRepo`), `-Remote origin`, `-Branch main`,
`-Token`, `-Force` (skip safety checks), `-DryRun`, `-WaitMinutes 20`.

## Fixing a release

| Problem | Fix |
|---|---|
| Typo in the release text | Edit `docs/releases/vX.Y.Z.md`, run `UpdateNotes -Version X.Y.Z`, commit the file. |
| Wrong or missing assets | `UploadAssets -Version X.Y.Z` (the version in `Constants.ps1` must match). |
| Workflow failed | Open the run in the Actions tab, fix the cause, then `UploadAssets -Version X.Y.Z` - or delete and publish again. |
| Released the wrong commit | `Delete -Version X.Y.Z -DeleteTag`, fix, `Publish -Version X.Y.Z`. Prefer a new patch version if users may already have updated. |

## First release of 3.0.0

The repository already contains the 3.0.0 CHANGELOG section and `docs/releases/v3.0.0.md`, so:

```powershell
.\tools\Release.ps1 Init
.\tools\Release.ps1 Status
.\tools\Release.ps1 Publish -Version 3.0.0
```
