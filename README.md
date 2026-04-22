# gha-supply-chain-claude

A GitHub Action that audits GitHub Actions references themselves for supply chain attacks using Claude.

When a PR modifies any workflow file (`.github/workflows/**.y{a,}ml`) or composite action definition (`**/action.y{a,}ml`), this action:

1. Scans every workflow and composite-action YAML in the repo at the PR's head and base
2. Extracts every `uses: owner/repo@ref` reference (including reusable workflow refs)
3. For each added or changed reference, resolves both old and new refs to commit SHAs via the GitHub API
4. Downloads the action's source tarball at each SHA and performs a local file-by-file diff
5. Sends the diff to Claude for security analysis
6. Flags any non-SHA pin (tags, branches, partial SHAs) as a finding in the same comment
7. Posts a single PR comment with per-reference risk verdicts

## What it detects

- Reading `GITHUB_TOKEN`, `ACTIONS_RUNTIME_TOKEN`, or OIDC tokens and exfiltrating them
- Writing to `$GITHUB_ENV`, `$GITHUB_PATH`, `$GITHUB_OUTPUT` to poison downstream steps
- `::add-mask::` / `core.setSecret` bypasses and secret-logging patterns
- Obfuscated JavaScript in `dist/index.js` (base64 decoding, `eval`, dynamic `require`)
- Composite-action `run:` steps that `curl | sh` or `wget | bash` remote scripts
- `child_process.exec` / shell invocations with dynamically built command strings
- `post:` / `pre:` hooks running unexpected code outside the main action entry
- Self-hosted runner persistence: writes to `$HOME`, crontabs, shell init files
- Reading credential files (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.docker/config.json`)
- `GITHUB_TOKEN` being used beyond the action's stated purpose (creating issues, pushing, etc.)
- Bundled binaries added without corresponding source changes
- Significant functionality changes that don't match the action's stated purpose
- Non-SHA ref pins (flagged with severity scaled by mutability — tags medium, branches high)

## Usage

Add this workflow to your repository at `.github/workflows/supply-chain-audit.yml`:

```yaml
name: GitHub Actions Supply Chain Audit

on:
  pull_request:
    paths:
      - ".github/workflows/**.yml"
      - ".github/workflows/**.yaml"
      - "**/action.yml"
      - "**/action.yaml"

permissions:
  contents: read
  pull-requests: write

jobs:
  audit:
    name: Audit workflow dependency changes
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: originsec/gha-supply-chain-claude@main
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `anthropic_api_key` | Yes | — | Anthropic API key for Claude |
| `model` | No | `claude-sonnet-4-20250514` | Claude model to use |
| `base_ref` | No | Auto-detected from PR | Git ref to diff against |
| `github_token` | No | `${{ github.token }}` | Token for GitHub API (commits + tarball endpoints) |

### Secrets

Add `ANTHROPIC_API_KEY` to your repository secrets (Settings → Secrets and variables → Actions).

## PR comment output

The action posts a single comment summarizing all findings. High and critical verdicts are shown expanded; low/medium/none are collapsed inside `<details>`. Every comment carries a transitivity banner noting that only direct `uses:` references are audited.

Three finding types appear in one comment:
- **Audit verdicts** — Claude's analysis of the action's source diff between the old and new refs (or the full source for a newly-added reference).
- **Pinning findings** — one per added/modified `uses:` that isn't pinned to a full 40-char commit SHA. Severity is **high** for branch-like refs (`@main`, `@master`) and **medium** for tags (`@v4`, `@v1.2.3`) and partial SHAs.
- **Docker findings** — one per newly-introduced `uses: docker://...` reference. Digest-pinned (`@sha256:...`) is **low** severity noting source audit is unavailable; tag-pinned is **medium**.

## Suppression

Add `[supply-chain-audit-ok]` to your PR description to skip the audit for a specific PR.

## Known limitations

This tool is intentionally scoped. Things it does **not** do:

### Docker container actions

References like `uses: docker://alpine:3.18` are **not source-audited**. Container actions are bundles of pre-built layers rather than a git source tree, and diffing image layers is a different problem than diffing action source. The tool emits a finding flagging every Docker ref that is not pinned by `@sha256:...` digest, but it never inspects the image contents. Audit the image yourself, pin by digest, and prefer first-party base images.

### Silent upstream repointing of branch and tag refs

A reference like `uses: actions/checkout@v4` resolves at run time to whatever commit the `v4` tag currently points at. A malicious or compromised maintainer can force-move the tag (this is exactly what happened with `tj-actions/changed-files` and several other well-known GHA compromises), and the workflow file in your repo never changes.

This tool audits source diffs **at PR time** — that is, when the ref string in your workflow file changes. It does **not** catch tag or branch drift that happens between PRs. The mitigation is to pin every `uses:` to a full 40-char SHA; the tool emits a pinning finding for every non-SHA ref to nudge you in that direction. A future "drift mode" could periodically re-resolve refs on `main` and flag divergence, but that is not in v1.

### Transitive dependencies

If `actions/foo@v1` internally uses `actions/bar@v2`, only `actions/foo@v1` is audited — `actions/bar@v2` (a dependency-of-a-dependency) is not followed. The PR comment includes a banner making this explicit. Rationale:

- There is no lockfile that pre-resolves the transitive tree (unlike npm/cargo), so every hop would require a fresh API resolve and source fetch.
- Findings several hops deep are difficult for the PR author to remediate — they don't control the intermediate action.
- Empirically, well-known GHA supply chain compromises (`tj-actions/changed-files`, `reviewdog`) compromised the directly-referenced action's own code.

Capped-depth recursion could be added in a future version.

### Local path actions

References like `uses: ./.github/actions/my-local-action` point to code already in the repo and are not fetched or diffed. Treat them as ordinary in-repo code and review them in the PR itself.

### Reusable workflows

References of the form `owner/repo/.github/workflows/foo.yml@ref` **are** audited the same way as actions (the source diff of the repo at the two refs is fed to Claude). However, reusable workflows inherit the caller's permissions and secrets, which can't be inferred from source diff alone. Review the `permissions:` and `secrets:` blocks in the caller manually.

## How it works

Each `uses:` reference is resolved via `GET /repos/{owner}/{repo}/commits/{ref}` to a commit SHA, and the source tree at that SHA is downloaded via `GET /repos/{owner}/{repo}/tarball/{sha}`. Old and new tarballs are extracted into temp dirs and diffed file-by-file with Python's `difflib`. The diff is sent to Claude with a system prompt tuned for GHA-specific attack patterns, modeled on real incidents.

The GitHub API is called with `GITHUB_TOKEN` (the default action token), which gives 5000 authenticated requests per hour — plenty for all but the largest PR diffs.

## Requirements

- Python 3.10+ (available on `ubuntu-latest` runners)
- `fetch-depth: 0` on checkout (needed to diff against the base branch)
- `GITHUB_TOKEN` with read access to any referenced public repos (the default runner token is sufficient)

## License

Prelude Research License — see [LICENSE](LICENSE) for details.
