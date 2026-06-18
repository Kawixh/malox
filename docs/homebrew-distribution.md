# Homebrew Distribution Guide

Research checked on 2026-06-18.

This guide explains how to publish Malox through a Homebrew tap so users can run:

```bash
brew install Kawixh/tap/malox
```

It also explains how upgrades work after each GitHub release.

## Current Repo State

Malox already has the release pieces needed for Homebrew:

- `.github/workflows/release.yml` runs on pushes to `main`.
- `.goreleaser.yml` builds macOS, Linux, and Windows binaries.
- `.goreleaser.yml` publishes a Homebrew formula to `Kawixh/homebrew-tap`.
- The formula path is `Formula/malox.rb`.
- The Homebrew install command is `brew install Kawixh/tap/malox`.

The remaining setup is mostly GitHub repository and secret setup.

## How Homebrew Tap Names Work

Homebrew tap names map to GitHub repositories.

For the one-argument tap form:

```bash
brew tap Kawixh/tap
```

Homebrew looks for:

```text
https://github.com/Kawixh/homebrew-tap
```

The repository prefix `homebrew-` matters on GitHub, but users omit it in the
command. That is why the public install command is:

```bash
brew install Kawixh/tap/malox
```

Do not use npm-style names such as `@dark`; that is not a Homebrew tap naming
convention.

## Step 1: Create The Tap Repository

Create a separate GitHub repository:

```text
Kawixh/homebrew-tap
```

Recommended settings:

- Visibility: public, unless you intentionally want private distribution.
- Default branch: `main`.
- Initial contents: a README is fine.
- Directory expected after first release: `Formula/`.

Do not manually create `Formula/malox.rb` unless you are testing locally.
GoReleaser will create and update it during release.

## Step 2: Create A Fine-Grained GitHub Token

The normal `GITHUB_TOKEN` can publish the release in the main Malox repository,
but it cannot reliably push to a separate tap repository. Create a fine-grained
personal access token for the tap.

Token setup:

- Resource owner: `Kawixh`.
- Repository access: only `Kawixh/homebrew-tap`.
- Permission: `Contents: Read and write`.
- Expiration: choose what you are comfortable rotating.

Copy the token once GitHub shows it.

## Step 3: Add The Secret To The Malox Repo

In the main `Kawixh/malox` repository:

1. Open GitHub repository settings.
2. Go to `Secrets and variables`.
3. Open `Actions`.
4. Create a repository secret named:

```text
HOMEBREW_TAP_GITHUB_TOKEN
```

5. Paste the fine-grained token from Step 2.

The release workflow already passes this secret to GoReleaser.

## Step 4: Confirm GoReleaser Tap Settings

The important `.goreleaser.yml` section is:

```yaml
brews:
  - name: malox
    repository:
      owner: Kawixh
      name: homebrew-tap
      branch: main
      token: "{{ .Env.HOMEBREW_TAP_GITHUB_TOKEN }}"
    directory: Formula
    install: |
      bin.install "malox"
    test: |
      system "#{bin}/malox", "--version"
```

This tells GoReleaser to commit `Formula/malox.rb` into
`Kawixh/homebrew-tap` after a release.

GoReleaser currently marks its Homebrew formula publisher as deprecated in favor
of casks. Malox still uses `brews` here because the target distribution model is
a CLI formula installed with `brew install Kawixh/tap/malox`. Revisit this only
if GoReleaser removes formula support or the project decides to ship a cask.

## Step 5: Release A Version

Malox uses a low-ceremony release flow:

```bash
git push origin main
```

The release workflow:

1. Finds the latest `vX.Y.Z` tag.
2. Chooses the next version.
3. Creates release notes.
4. Creates and pushes the new tag.
5. Runs GoReleaser.
6. Publishes GitHub release artifacts.
7. Updates `Kawixh/homebrew-tap` with the new formula.

To force a specific bump, create `.release-bump` before pushing:

```text
patch
```

Allowed values:

```text
major
minor
patch
```

Remove `.release-bump` after the release unless you want the same override to
apply again.

## Step 6: Install From Brew

After the release workflow finishes and the tap repo receives `Formula/malox.rb`,
install with:

```bash
brew install Kawixh/tap/malox
```

Verify:

```bash
malox --version
```

Useful inspection commands:

```bash
brew info Kawixh/tap/malox
brew list malox
brew test Kawixh/tap/malox
```

## Step 7: Upgrade From Brew

When a newer Malox release is published, GoReleaser updates the tap formula.
Users can upgrade with:

```bash
brew update
brew upgrade malox
```

Or fully qualified:

```bash
brew update
brew upgrade Kawixh/tap/malox
```

To check before upgrading:

```bash
brew outdated malox
brew outdated --json=v2 malox
```

Homebrew updates tap repositories during `brew update`, and `brew upgrade`
upgrades outdated installed formulae.

## Step 8: Troubleshoot The First Release

If `brew install Kawixh/tap/malox` cannot find the formula:

```bash
brew tap Kawixh/tap
brew update
brew search malox
```

Check the tap repository:

```text
https://github.com/Kawixh/homebrew-tap/blob/main/Formula/malox.rb
```

If the formula was not committed, check the release workflow logs for:

- missing `HOMEBREW_TAP_GITHUB_TOKEN`
- token without `Contents: Read and write`
- token scoped to the wrong repository
- tap repository name not matching `homebrew-tap`

If the formula exists but install fails, run:

```bash
brew install --debug --verbose Kawixh/tap/malox
```

## Useful References

- Homebrew taps: https://docs.brew.sh/Taps
- Homebrew formula cookbook: https://docs.brew.sh/Formula-Cookbook
- Homebrew command manpage: https://docs.brew.sh/Manpage
- GoReleaser Homebrew formulas: https://goreleaser.com/customization/publish/homebrew_formulas/
