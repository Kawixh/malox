# Milestone 11: Homebrew Distribution And Update Checks

## Purpose

Make Malox easy to install, upgrade, and keep current while preserving fast scan
startup and non-blocking CLI behavior.

## Scope

- Document and verify Homebrew tap distribution for:
  - `Kawixh/homebrew-tap`
  - `Formula/malox.rb`
  - `brew install Kawixh/tap/malox`
  - `brew upgrade malox`
- Keep release automation compatible with the existing push-to-main GoReleaser
  flow.
- Add a package update checker for the Malox CLI itself.
- Check the latest GitHub release in parallel with command execution.
- Use the GitHub latest release endpoint:
  - `GET https://api.github.com/repos/Kawixh/malox/releases/latest`
- Compare the running version with the latest stable release tag.
- Show update status only in interactive human-readable output.
- Keep JSON output, machine-readable output, and command exit codes unaffected by
  update-check results.
- Cache update-check metadata under the global Malox cache.

## Out Of Scope

- Auto-updating the binary from inside Malox.
- Running `brew upgrade` from inside Malox.
- Blocking scans until the update check finishes.
- Checking prereleases by default.
- Prompting users for telemetry or sending scan/project metadata.
- Replacing Homebrew's own outdated or upgrade behavior.

## CLI Requirements

- Human output may start with:
  - `Checking for updates...`
- If a newer release is found, replace that status with:
  - `Update found: v0.2.0 -> v0.3.0, released 2 days ago`
- If the latest release matches the running version, either remove the status line
  or show:
  - `Malox is up to date: v0.3.0`
- If the update check is slow or unavailable, continue the requested command and
  do not fail the scan.
- If the command finishes before the update check returns, do not delay command
  completion just to print update status.
- Support disabling update checks with:
  - `--no-update-check`
  - `MALOX_NO_UPDATE_CHECK=1`
- Keep update-check messages out of `--json` output.

## Implementation Constraints

- Start the update check in a goroutine from CLI boundary code, not from scanner
  packages.
- Give the update check its own timeout and context derived from the command
  context.
- Do not let update-check cancellation cancel the scan.
- Use direct Go HTTP client code with bounded timeout and clear user agent.
- Parse only the fields needed from the GitHub response:
  - `tag_name`
  - `html_url`
  - `created_at`
  - `published_at`
  - `prerelease`
  - `draft`
- Prefer `published_at` for user-facing release age; fall back to `created_at`
  only when needed.
- Compare semantic versions after trimming a leading `v`.
- Treat malformed, empty, development, or snapshot versions as not comparable.
- Do not print update failures in normal output; expose them only through debug
  logging or structured diagnostics.
- Cache successful checks with a short TTL, such as 6 to 24 hours, so every CLI
  invocation does not hit GitHub.
- Do not send project paths, package names, dependency inventory, findings, or
  local configuration to the update endpoint.

## Temporary Data Or Implementation

- The first version may support only GitHub Releases because the current release
  pipeline publishes there.
- Formula livecheck may be documented later, but Malox's own update notification
  should not depend on Homebrew being installed.
- If no stable release exists yet, the checker should quietly report no update
  rather than treating the first run as an error.

## Passing Criteria

- Installing from Homebrew works after a published release:
  - `brew install Kawixh/tap/malox`
- Upgrading from Homebrew works after a newer release:
  - `brew update`
  - `brew upgrade malox`
- A command can run while the update check is in flight.
- Slow or failed update checks do not change scan results, JSON output, or exit
  codes.
- Interactive output replaces `Checking for updates...` with an update-found line
  when a newer release is available before command completion.
- Release age is formatted as minutes, hours, or days.
- Unit tests cover newer version, equal version, malformed version, prerelease,
  draft release, network timeout, cached result, disabled checks, and JSON output
  suppression.
- Tests use local HTTP test servers or cached fixture responses, not live GitHub
  calls.
