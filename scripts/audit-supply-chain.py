"""Audit changed GitHub Actions references for supply chain attacks.

Parses every workflow file and composite-action definition in the repository,
extracts each ``uses:`` reference, and for every added or changed reference
downloads the action source at both old and new SHAs from GitHub's tarball
endpoint, diffs them locally, and feeds each diff to Claude. Outputs a
Markdown PR comment to stdout.

Usage:
    python3 scripts/audit-supply-chain.py [base-ref]

base-ref defaults to origin/main.

Requires:
    ANTHROPIC_API_KEY — Claude API key
    GITHUB_TOKEN      — token for GitHub API (commits + tarball endpoints)
"""

from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GITHUB_API = "https://api.github.com"
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-20250514"
ANTHROPIC_API_VERSION = "2023-06-01"
USER_AGENT = "gha-supply-chain-audit/1.0 (github.com/originsec/gha-supply-chain-claude)"
FETCH_DELAY = 0.25  # courtesy delay between GitHub API fetches (seconds)
MAX_COMMENT_CHARS = 60_000
# Cap the diff payload sent to Claude. Well under Sonnet's 200k token limit
# even at worst-case ~2 chars/token for minified JS; leaves headroom for the
# system prompt, user wrapper, and response.
MAX_DIFF_CHARS = 150_000
SUPPRESS_MARKER = "[supply-chain-audit-ok]"

# Workflow YAMLs live under .github/workflows; composite actions live in
# action.yml (or action.yaml) at any path.
WORKFLOW_FILE_RE = re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$")
ACTION_FILE_RE = re.compile(r"(?:^|/)action\.ya?ml$")

# A 40-char lowercase hex SHA pin is the only form considered safely immutable.
SHA_PIN_RE = re.compile(r"^[0-9a-f]{40}$")

SYSTEM_PROMPT = """\
You are a supply chain security auditor for GitHub Actions. You analyze diffs \
between versions of a referenced action's source code to detect signs of supply \
chain attacks, malicious code injection, or suspicious changes.

Evaluate the diff and produce a JSON verdict with these fields:
- "risk": one of "none", "low", "medium", "high", "critical"
- "summary": a 1-2 sentence summary of your findings
- "findings": an array of objects, each with:
    - "severity": "low", "medium", "high", or "critical"
    - "description": what you found and why it is suspicious
    - "evidence": the relevant code snippet, file path, or pattern

Signals specific to GitHub Actions:
1. Reading GITHUB_TOKEN, ACTIONS_RUNTIME_TOKEN, ACTIONS_ID_TOKEN_REQUEST_TOKEN, \
   ACTIONS_CACHE_URL, or ACTIONS_RESULTS_URL and exfiltrating via HTTP, DNS, or \
   writing to disk
2. Writing to $GITHUB_ENV, $GITHUB_PATH, or $GITHUB_OUTPUT to poison downstream \
   steps — especially appending to PATH, overriding well-known env vars, or \
   setting outputs consumed by later jobs
3. Logging or leaking secrets. Bypasses of ::add-mask:: or core.setSecret. \
   Echoing values of process.env / env. in a way that could surface in logs
4. JavaScript actions: obfuscated bundled code in dist/index.js. Dynamic require() \
   or eval(). Fetch/axios/http calls to unfamiliar domains. child_process.exec \
   with dynamically built command strings. Writes outside the workspace \
   (os.homedir(), /tmp, /etc)
5. Composite/shell actions: `run:` steps that curl | sh or wget | bash a remote \
   script. Commands dynamically built from untrusted inputs. Installing \
   unexpected packages
6. Docker container actions: pulling base images by tag rather than digest. \
   ENTRYPOINT or CMD that fetches remote code at runtime
7. Checkout manipulation: self-amending commits, pushes back to the repo, \
   branch deletes, force-pushes — especially with persist-credentials
8. Changes to action.yml inputs/outputs that silently widen privileges or \
   redirect outputs to attacker-controlled destinations
9. post: or pre: hooks that run unexpected code outside the main action entry
10. Self-hosted runner persistence: writes to $HOME, /etc, /opt, installed \
    services, or crontabs; modifications to shell init files
11. Reading files outside the workspace (~/.ssh, ~/.aws, ~/.gnupg, ~/.npmrc, \
    ~/.docker/config.json, browser profile directories)
12. Calls to the GitHub API with the provided token that go beyond the action's \
    stated purpose — creating issues, forking, starring, following users, \
    invoking workflows, updating protected branches
13. Changes that introduce new runtime dependencies (npm install, pip install, \
    apt-get install) that weren't present before, especially installing from \
    non-standard registries
14. Code collecting system information (hostname, env dump, installed software) \
    and sending to a remote endpoint
15. Significant functionality additions that don't match the action's stated \
    purpose
16. Removal or weakening of existing security checks or input validation
17. Bundled binaries (.exe, .so, .dll, .node, .wasm) added or changed without \
    corresponding source changes in the same crate/package

For "none" risk: routine version bumps, docs, bug fixes, feature additions \
consistent with the action's purpose.
For "low" risk: minor concerns worth noting but likely benign.
For "medium" risk: unusual patterns that warrant manual review.
For "high" risk: strong indicators of potentially malicious behavior.
For "critical" risk: clear evidence of malicious code or supply chain attack techniques.

Respond ONLY with the JSON object. No markdown fences, no commentary.\
"""

# ---------------------------------------------------------------------------
# YAML parsing
# ---------------------------------------------------------------------------
#
# We intentionally parse ``uses:`` references with a regex rather than a full
# YAML library. Reasons:
#   - Avoids a PyYAML dependency on runners (stdlib-only).
#   - Works identically on workflow files (steps.*.uses and jobs.*.uses for
#     reusable workflows) and composite action.yml files (runs.steps.*.uses).
#   - Ignores commented-out lines cleanly.
# The regex matches "uses:" followed by the reference string on the same line,
# optionally quoted. Values we care about look like:
#   owner/repo@ref
#   owner/repo/subpath@ref          (reusable workflow or action in subdir)
#   ./path                          (local action — skipped)
#   docker://image[:tag|@digest]    (container action — flagged but not diffed)

USES_LINE_RE = re.compile(
    r"""^\s*                       # leading whitespace
        (?:-\s+)?                  # optional list marker
        uses:\s*                   # the uses: key
        ['\"]?                     # optional opening quote
        (?P<value>[^'\"\s#]+)      # the reference value
        ['\"]?                     # optional closing quote
        \s*(?:\#.*)?$              # optional inline comment
    """,
    re.VERBOSE,
)


@dataclass
class UsesRef:
    """A single ``uses:`` reference found in a workflow or action file.

    For standard actions (``owner/repo@ref``), ``subpath`` is empty.
    For actions in subdirs (``owner/repo/path@ref``) and reusable workflows
    (``owner/repo/.github/workflows/foo.yml@ref``), ``subpath`` captures the
    path between the repo and the ``@ref`` separator.
    """

    owner: str
    repo: str
    subpath: str  # "" for top-level action
    ref: str
    file_path: str
    kind: str  # "action" | "reusable-workflow" | "docker" | "local"

    @property
    def key(self) -> tuple[str, str, str]:
        """Identity key: same owner/repo/subpath regardless of ref."""
        return (self.owner, self.repo, self.subpath)

    @property
    def display(self) -> str:
        """Human-readable owner/repo[/subpath]@ref."""
        base = f"{self.owner}/{self.repo}"
        if self.subpath:
            base += f"/{self.subpath}"
        return f"{base}@{self.ref}"

    def is_sha_pinned(self) -> bool:
        return bool(SHA_PIN_RE.match(self.ref))


def parse_uses_value(value: str, file_path: str) -> UsesRef | None:
    """Parse a single ``uses:`` value into a UsesRef, or None if unsupported."""
    if value.startswith("./") or value.startswith("../") or value == ".":
        # Local action — not externally auditable; caught by ordinary PR review.
        return None

    if value.startswith("docker://"):
        # Container action. Flagged at the call site but not source-diffed.
        return UsesRef(
            owner="",
            repo="",
            subpath=value[len("docker://") :],
            ref="",
            file_path=file_path,
            kind="docker",
        )

    # owner/repo[/subpath]@ref
    if "@" not in value:
        return None
    path_part, _, ref = value.partition("@")
    if not ref:
        return None
    segments = path_part.split("/")
    if len(segments) < 2:
        return None
    owner, repo = segments[0], segments[1]
    subpath = "/".join(segments[2:])
    if not owner or not repo:
        return None

    kind = "reusable-workflow" if subpath.endswith((".yml", ".yaml")) else "action"
    return UsesRef(
        owner=owner,
        repo=repo,
        subpath=subpath,
        ref=ref,
        file_path=file_path,
        kind=kind,
    )


def extract_uses_refs(text: str, file_path: str) -> list[UsesRef]:
    """Find every ``uses:`` reference in a workflow or action YAML text."""
    refs: list[UsesRef] = []
    for line in text.splitlines():
        # Strip full-line comments fast
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        m = USES_LINE_RE.match(line)
        if not m:
            continue
        parsed = parse_uses_value(m.group("value"), file_path)
        if parsed is not None:
            refs.append(parsed)
    return refs


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def is_relevant_yaml(path: str) -> bool:
    return bool(WORKFLOW_FILE_RE.search(path) or ACTION_FILE_RE.search(path))


def list_tree_files(ref: str) -> list[str]:
    """List every file at the given ref relevant to audit (workflow/action YAMLs)."""
    try:
        output = subprocess.check_output(
            ["git", "ls-tree", "-r", "--name-only", ref],
            text=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        print(
            f"::warning::git ls-tree at {ref} failed: {e.stderr.strip()}",
            file=sys.stderr,
        )
        return []
    return [line for line in output.splitlines() if is_relevant_yaml(line)]


def discover_changed_yaml_files(base_ref: str) -> list[str]:
    """Return workflow/action YAML paths changed between base_ref and HEAD."""
    try:
        output = subprocess.check_output(
            ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
            text=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        print(
            f"::warning::git diff against {base_ref} failed: {e.stderr.strip()}",
            file=sys.stderr,
        )
        return []
    return [line for line in output.splitlines() if is_relevant_yaml(line)]


def read_file_at(ref: str, path: str) -> str | None:
    """Read a file at a specific git ref. Returns None if missing."""
    try:
        return subprocess.check_output(
            ["git", "show", f"{ref}:{path}"],
            text=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError:
        return None


def read_file_head(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Change classification
# ---------------------------------------------------------------------------


@dataclass
class RefChange:
    """A single ``uses:`` reference that changed between base and head."""

    owner: str
    repo: str
    subpath: str
    old_ref: str | None  # None when the reference is newly introduced
    new_ref: str
    kind: str  # "action" | "reusable-workflow" | "docker" | "local"
    head_refs: list[UsesRef] = field(default_factory=list)  # where it appears in head


def classify_changes(
    base_refs: list[UsesRef], head_refs: list[UsesRef]
) -> list[RefChange]:
    """Group refs by (owner, repo, subpath) and find adds / ref changes.

    Removed refs (in base, not in head) are intentionally dropped: no supply
    chain risk to code being removed.
    """
    base_by_key: dict[tuple[str, str, str], set[str]] = {}
    for r in base_refs:
        if r.kind in ("docker", "local"):
            continue
        base_by_key.setdefault(r.key, set()).add(r.ref)

    head_by_key: dict[tuple[str, str, str], list[UsesRef]] = {}
    for r in head_refs:
        if r.kind in ("docker", "local"):
            continue
        head_by_key.setdefault(r.key, []).append(r)

    changes: list[RefChange] = []
    for key, head_list in head_by_key.items():
        head_versions = {r.ref for r in head_list}
        base_versions = base_by_key.get(key, set())

        # Unchanged: same ref set
        if head_versions == base_versions:
            continue

        sample = head_list[0]

        if key not in base_by_key:
            # Entirely new dependency
            for ref in sorted(head_versions):
                changes.append(
                    RefChange(
                        owner=sample.owner,
                        repo=sample.repo,
                        subpath=sample.subpath,
                        old_ref=None,
                        new_ref=ref,
                        kind=sample.kind,
                        head_refs=[r for r in head_list if r.ref == ref],
                    )
                )
        else:
            removed = sorted(base_versions - head_versions)
            added = sorted(head_versions - base_versions)
            # Pair one-to-one by position; leftover adds become new-dep entries.
            for i, new_ref in enumerate(added):
                old_ref = removed[i] if i < len(removed) else None
                changes.append(
                    RefChange(
                        owner=sample.owner,
                        repo=sample.repo,
                        subpath=sample.subpath,
                        old_ref=old_ref,
                        new_ref=new_ref,
                        kind=sample.kind,
                        head_refs=[r for r in head_list if r.ref == new_ref],
                    )
                )

    # Sort for deterministic output
    changes.sort(key=lambda c: (c.owner, c.repo, c.subpath, c.new_ref))
    return changes


def collect_docker_refs(head_refs: list[UsesRef]) -> list[UsesRef]:
    return [r for r in head_refs if r.kind == "docker"]


# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------


def _github_request(url: str, token: str | None, accept: str) -> bytes:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def resolve_sha(owner: str, repo: str, ref: str, token: str | None) -> str | None:
    """Resolve a ref (tag/branch/SHA) to a full commit SHA via the GitHub API."""
    if SHA_PIN_RE.match(ref):
        return ref
    url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{ref}"
    try:
        data = json.loads(_github_request(url, token, "application/vnd.github+json"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        print(
            f"::warning::Failed to resolve {owner}/{repo}@{ref}: {e}",
            file=sys.stderr,
        )
        return None
    sha = data.get("sha")
    return sha if isinstance(sha, str) else None


def download_tarball(
    owner: str, repo: str, sha: str, dest_dir: Path, token: str | None
) -> Path | None:
    """Download an action's source tarball at a specific SHA."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/tarball/{sha}"
    dest = dest_dir / f"{owner}-{repo}-{sha}.tar.gz"
    try:
        data = _github_request(url, token, "application/vnd.github+json")
        dest.write_bytes(data)
    except (urllib.error.URLError, OSError) as e:
        print(
            f"::warning::Failed to download {owner}/{repo}@{sha}: {e}",
            file=sys.stderr,
        )
        return None
    return dest


def extract_tarball(archive: Path, dest_dir: Path) -> Path | None:
    """Extract a GitHub source tarball. Returns the single top-level directory."""
    try:
        with tarfile.open(archive, "r:gz") as tf:
            if hasattr(tarfile, "data_filter"):
                tf.extractall(dest_dir, filter="data")
            else:
                for member in tf.getmembers():
                    resolved = (dest_dir / member.name).resolve()
                    if not str(resolved).startswith(str(dest_dir.resolve())):
                        print(
                            f"::warning::Path traversal in {archive.name}: {member.name}",
                            file=sys.stderr,
                        )
                        return None
                tf.extractall(dest_dir)
    except (tarfile.TarError, OSError) as e:
        print(f"::warning::Failed to extract {archive.name}: {e}", file=sys.stderr)
        return None

    dirs = [item for item in dest_dir.iterdir() if item.is_dir()]
    if len(dirs) == 1:
        return dirs[0]
    return dest_dir if any(dest_dir.iterdir()) else None


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------


def is_binary(path: Path) -> bool:
    try:
        return b"\x00" in path.read_bytes()[:8192]
    except OSError:
        return True


def collect_files(directory: Path | None) -> dict[str, Path]:
    files: dict[str, Path] = {}
    if directory is None:
        return files
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            rel = str(path.relative_to(directory)).replace("\\", "/")
            files[rel] = path
    return files


def diff_trees(old_dir: Path | None, new_dir: Path) -> str:
    """Produce a unified diff between two extracted action source trees."""
    old_files = collect_files(old_dir)
    new_files = collect_files(new_dir)
    all_paths = sorted(set(old_files) | set(new_files))
    parts: list[str] = []

    for rel in all_paths:
        old_p = old_files.get(rel)
        new_p = new_files.get(rel)

        if old_p and new_p:
            if is_binary(old_p) or is_binary(new_p):
                os_ = old_p.stat().st_size
                ns_ = new_p.stat().st_size
                if os_ != ns_:
                    parts.append(f"Binary file {rel} changed ({os_} -> {ns_} bytes)\n")
                continue
            try:
                old_lines = old_p.read_text(errors="replace").splitlines(keepends=True)
                new_lines = new_p.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            d = difflib.unified_diff(
                old_lines, new_lines, fromfile=f"a/{rel}", tofile=f"b/{rel}"
            )
            text = "".join(d)
            if text:
                parts.append(text)

        elif new_p:
            if is_binary(new_p):
                parts.append(f"Binary file {rel} added ({new_p.stat().st_size} bytes)\n")
                continue
            try:
                lines = new_p.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            d = difflib.unified_diff([], lines, fromfile="/dev/null", tofile=f"b/{rel}")
            parts.append("".join(d))

        elif old_p:
            if is_binary(old_p):
                parts.append(f"Binary file {rel} removed ({old_p.stat().st_size} bytes)\n")
                continue
            try:
                lines = old_p.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            d = difflib.unified_diff(lines, [], fromfile=f"a/{rel}", tofile="/dev/null")
            parts.append("".join(d))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Claude API
# ---------------------------------------------------------------------------


def _truncate_diff(diff_text: str) -> tuple[str, bool]:
    """Cap diff_text at MAX_DIFF_CHARS; return (maybe-truncated-text, was_truncated)."""
    if len(diff_text) <= MAX_DIFF_CHARS:
        return diff_text, False
    truncated = diff_text[:MAX_DIFF_CHARS]
    omitted = len(diff_text) - MAX_DIFF_CHARS
    truncated += (
        f"\n\n... (diff truncated: {omitted} characters omitted to fit within "
        f"Claude's context window; audit only reflects the leading "
        f"{MAX_DIFF_CHARS} characters)\n"
    )
    return truncated, True


def call_claude(
    display: str,
    old_ref: str | None,
    new_ref: str,
    kind: str,
    diff_text: str,
    api_key: str,
    model: str,
) -> dict:
    """Call Claude to audit an action diff. Returns the parsed verdict dict."""
    diff_text, was_truncated = _truncate_diff(diff_text)
    truncation_note = (
        "\n\nNote: the diff exceeded the size limit and was truncated. "
        "Reflect this uncertainty in your verdict — do not claim confidence "
        "about un-inspected regions.\n"
        if was_truncated
        else ""
    )
    if old_ref is None:
        user_msg = (
            f'Analyze the following contents for the newly added GitHub Actions '
            f'reference "{display}" ({kind}).\n\n'
            f"This is a new action dependency. All file contents are shown as "
            f"additions. Pay special attention to whether the action's stated "
            f"purpose matches its code and whether it contains any suspicious "
            f"functionality.{truncation_note}\n\n"
            f"<diff>\n{diff_text}\n</diff>"
        )
    else:
        user_msg = (
            f'Analyze the following diff for the GitHub Actions reference '
            f'"{display}" ({kind}, ref changed from {old_ref} to {new_ref}).\n\n'
            f"The diff shows all file changes in the action's source repository "
            f"between the two refs.{truncation_note}\n\n"
            f"<diff>\n{diff_text}\n</diff>"
        )

    body = json.dumps(
        {
            "model": model,
            "max_tokens": 4096,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_msg}],
        }
    ).encode()

    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": api_key,
        "Anthropic-Version": ANTHROPIC_API_VERSION,
        "User-Agent": USER_AGENT,
    }
    req = urllib.request.Request(CLAUDE_API_URL, data=body, headers=headers, method="POST")

    last_err = None
    text = ""
    for attempt in range(2):
        if attempt > 0:
            time.sleep(5)
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                result = json.loads(resp.read())
            text = ""
            for block in result.get("content", []):
                if block.get("type") == "text":
                    text += block["text"]
            text = text.strip()
            if text.startswith("```"):
                text = re.sub(r"^```\w*\n?", "", text)
                text = re.sub(r"\n?```$", "", text)
                text = text.strip()
            # raw_decode tolerates trailing commentary after the JSON object
            parsed, _ = json.JSONDecoder().raw_decode(text)
            return parsed
        except json.JSONDecodeError as e:
            last_err = f"Invalid JSON from Claude: {e}\nRaw response: {text[:500]}"
        except urllib.error.HTTPError as e:
            # Capture the response body — the Anthropic API includes an error
            # type + message that's essential for diagnosing 400s.
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = "<unreadable>"
            last_err = f"API request failed: {e} — {body[:500]}"
        except (urllib.error.URLError, OSError) as e:
            last_err = f"API request failed: {e}"

    return {
        "risk": "high",
        "summary": f"Audit failed — manual review required. Error: {last_err}",
        "findings": [],
    }


# ---------------------------------------------------------------------------
# Comment formatting
# ---------------------------------------------------------------------------

RISK_EMOJI = {
    "none": "✅",
    "low": "✅",
    "medium": "⚠️",
    "high": "\U0001f534",
    "critical": "\U0001f534",
}
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


@dataclass
class Verdict:
    display: str
    change: RefChange | None  # None for pinning / docker findings
    risk: str
    summary: str
    findings: list[dict]
    kind: str  # "audit" | "pinning" | "docker"


def format_comment(verdicts: list[Verdict]) -> str:
    """Format all verdicts into a single Markdown PR comment."""
    verdicts.sort(key=lambda v: RISK_ORDER.get(v.risk, 5))
    high_count = sum(1 for v in verdicts if v.risk in ("high", "critical"))
    total = len(verdicts)

    lines: list[str] = []
    lines.append("## GitHub Actions Supply Chain Audit\n")

    if high_count > 0:
        lines.append(
            f"> **{high_count}** of **{total}** findings flagged as high/critical risk.\n"
        )
    else:
        lines.append(f"> Analyzed **{total}** findings. No high-risk issues.\n")

    lines.append(
        "> ⚠ This audit only inspects direct `uses:` references in this repository. "
        "Transitive actions (actions that reference other actions) are not followed.\n"
    )

    for v in verdicts:
        emoji = RISK_EMOJI.get(v.risk, "❓")
        header = f"{emoji} **`{v.display}`** — **{v.risk}**"
        if v.kind == "pinning":
            header += " (pinning)"
        elif v.kind == "docker":
            header += " (docker)"

        expanded = v.risk in ("high", "critical")
        if expanded:
            lines.append(f"### {header}\n")
            lines.append(f"{v.summary}\n")
        else:
            lines.append(f"<details>\n<summary>{header}</summary>\n")
            lines.append(f"{v.summary}\n")

        for f in v.findings:
            sev = f.get("severity", "?")
            desc = f.get("description", "")
            evidence = f.get("evidence", "")
            lines.append(f"- **[{sev}]** {desc}")
            if evidence:
                lines.append(f"  ```\n  {evidence}\n  ```")

        if not expanded:
            lines.append("\n</details>\n")
        else:
            lines.append("")

    lines.append("---")
    lines.append(
        f"*Audit performed by Claude (`{os.environ.get('AUDIT_MODEL', DEFAULT_MODEL)}`) "
        f"via [gha-supply-chain-claude]"
        f"(https://github.com/originsec/gha-supply-chain-claude)*"
    )

    comment = "\n".join(lines)

    if len(comment) > MAX_COMMENT_CHARS:
        note = (
            "\n\n> **Note:** This comment was truncated due to GitHub's size limit. "
            "See CI logs for the full audit output.\n"
        )
        comment = comment[: MAX_COMMENT_CHARS - len(note)] + note
    return comment


# ---------------------------------------------------------------------------
# Pinning findings
# ---------------------------------------------------------------------------


BRANCH_LIKE_RE = re.compile(r"^(main|master|develop|dev|trunk|HEAD)$", re.IGNORECASE)


def pinning_verdict_for(change: RefChange) -> Verdict | None:
    """If the new ref is not a full SHA, return a pinning finding Verdict.

    The severity scales with how mutable the pointer is:
      - branch-looking names → high
      - anything else (tags, partial SHAs) → medium
    """
    ref = change.new_ref
    if SHA_PIN_RE.match(ref):
        return None

    display = _display_for(change)
    if BRANCH_LIKE_RE.match(ref):
        severity = "high"
        summary = (
            f"`{display}` is pinned to the branch-like ref `{ref}`, which can be "
            f"silently repointed by the action's maintainers. Pin to a full "
            f"40-char commit SHA instead."
        )
    else:
        severity = "medium"
        summary = (
            f"`{display}` is pinned to the tag/partial ref `{ref}`. Tags are "
            f"mutable and can be force-moved by the action's maintainers. "
            f"Pin to a full 40-char commit SHA for supply chain integrity."
        )
    return Verdict(
        display=display,
        change=change,
        risk=severity,
        summary=summary,
        findings=[
            {
                "severity": severity,
                "description": "Non-SHA pin detected",
                "evidence": f"uses: {display}",
            }
        ],
        kind="pinning",
    )


def docker_verdict_for(uses: UsesRef) -> Verdict:
    """Return a finding for a docker:// container action reference."""
    image = uses.subpath  # we stored the post-"docker://" value here
    digest_pinned = "@sha256:" in image
    if digest_pinned:
        severity = "low"
        summary = (
            f"Container action `docker://{image}` is digest-pinned. Source-level "
            f"diffing is not supported for Docker container actions, but digest "
            f"pinning makes the reference immutable."
        )
    else:
        severity = "medium"
        summary = (
            f"Container action `docker://{image}` is not pinned by digest. The "
            f"referenced image can change under this tag without any change to "
            f"the workflow file. Pin to `@sha256:...` and/or audit the image "
            f"manually; this tool cannot source-diff container actions."
        )
    return Verdict(
        display=f"docker://{image}",
        change=None,
        risk=severity,
        summary=summary,
        findings=[
            {
                "severity": severity,
                "description": "Docker container action — not source-audited",
                "evidence": f"uses: docker://{image}",
            }
        ],
        kind="docker",
    )


def _display_for(change: RefChange) -> str:
    base = f"{change.owner}/{change.repo}"
    if change.subpath:
        base += f"/{change.subpath}"
    return f"{base}@{change.new_ref}"


# ---------------------------------------------------------------------------
# Verdict cache
# ---------------------------------------------------------------------------
#
# An action's source at a full commit SHA is immutable (git content-addressing
# prevents a SHA from pointing at two different trees). Keying the cache by
# (owner/repo/subpath, old_sha, new_sha) yields entries that are safe to
# reuse across repos and PRs — the identity is looked up *after* we resolve
# any @tag or @branch to a full SHA via the GitHub API.

CACHE_VERSION = 1


def cache_key(display_no_ref: str, old_sha: str | None, new_sha: str | None) -> str:
    return f"{display_no_ref}|{old_sha or ''}|{new_sha or ''}"


def load_verdict_cache(path: str | None) -> dict[str, dict]:
    if not path:
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
        return {}
    entries = data.get("entries", {})
    return entries if isinstance(entries, dict) else {}


def save_verdict_cache(path: str | None, cache: dict[str, dict]) -> None:
    if not path:
        return
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump({"version": CACHE_VERSION, "entries": cache}, f)
    except OSError as e:
        print(f"::warning::Failed to save verdict cache: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _check_suppression() -> bool:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return False
    try:
        with open(event_path) as f:
            event = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False
    body = event.get("pull_request", {}).get("body") or ""
    return SUPPRESS_MARKER in body


def main() -> int:
    base_ref = sys.argv[1] if len(sys.argv) > 1 else "origin/main"

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("::error::ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 1
    model = os.environ.get("AUDIT_MODEL", DEFAULT_MODEL)
    gh_token = os.environ.get("GITHUB_TOKEN")

    if _check_suppression():
        print(
            f"Supply chain audit suppressed via '{SUPPRESS_MARKER}' in PR body.",
            file=sys.stderr,
        )
        return 0

    changed = discover_changed_yaml_files(base_ref)
    if not changed:
        print("No workflow or action YAML changes detected.", file=sys.stderr)
        return 0
    print(
        f"Auditing {len(changed)} changed YAML file(s): {', '.join(changed)}",
        file=sys.stderr,
    )

    # Parse every workflow/action YAML on both sides of the diff. We scan all
    # of them (not just the changed ones) to correctly classify references
    # that moved between files.
    base_files = list_tree_files(base_ref)
    head_files = list_tree_files("HEAD")

    base_refs: list[UsesRef] = []
    for path in base_files:
        text = read_file_at(base_ref, path)
        if text:
            base_refs.extend(extract_uses_refs(text, path))

    head_refs: list[UsesRef] = []
    for path in head_files:
        text = read_file_head(path)
        if text is None:
            # Fallback to git show at HEAD for files not in the working tree
            text = read_file_at("HEAD", path)
        if text:
            head_refs.extend(extract_uses_refs(text, path))

    # Restrict attention to refs introduced or modified in the changed files.
    # (A PR that didn't touch a given workflow file shouldn't re-audit its
    # unchanged references.)
    changed_set = set(changed)
    scoped_head_refs = [r for r in head_refs if r.file_path in changed_set]
    scoped_base_refs = [r for r in base_refs if r.file_path in changed_set]
    changes = classify_changes(scoped_base_refs, scoped_head_refs)

    # Pinning findings — emit for every added or modified ref regardless of
    # whether the source audit flagged anything.
    verdicts: list[Verdict] = []
    for change in changes:
        pin = pinning_verdict_for(change)
        if pin is not None:
            verdicts.append(pin)

    # Docker findings — only for container refs that are new or appear in
    # changed files (to avoid re-warning about unchanged pre-existing refs).
    scoped_docker = [r for r in scoped_head_refs if r.kind == "docker"]
    base_docker_keys = {
        (r.kind, r.subpath) for r in scoped_base_refs if r.kind == "docker"
    }
    for r in scoped_docker:
        if (r.kind, r.subpath) not in base_docker_keys:
            verdicts.append(docker_verdict_for(r))

    print(
        f"Classified {len(changes)} action ref change(s); "
        f"{sum(1 for v in verdicts if v.kind == 'pinning')} pinning finding(s); "
        f"{sum(1 for v in verdicts if v.kind == 'docker')} docker finding(s).",
        file=sys.stderr,
    )

    cache_path = os.environ.get("AUDIT_CACHE_FILE")
    cache = load_verdict_cache(cache_path)
    cache_hits = 0

    # Source-diff audit for each actual change
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for i, change in enumerate(changes):
            display = _display_for(change)
            print(
                f"[{i+1}/{len(changes)}] Auditing {display}...",
                file=sys.stderr,
            )

            new_sha = resolve_sha(change.owner, change.repo, change.new_ref, gh_token)
            if not new_sha:
                verdicts.append(
                    Verdict(
                        display=display,
                        change=change,
                        risk="high",
                        summary=(
                            f"Could not resolve `{change.new_ref}` to a commit SHA "
                            f"via the GitHub API. Manual review required."
                        ),
                        findings=[],
                        kind="audit",
                    )
                )
                continue

            old_sha = (
                resolve_sha(change.owner, change.repo, change.old_ref, gh_token)
                if change.old_ref
                else None
            )

            # Cache lookup keyed by resolved SHAs — immutable by git content-addressing.
            display_no_ref = f"{change.owner}/{change.repo}"
            if change.subpath:
                display_no_ref += f"/{change.subpath}"
            key = cache_key(display_no_ref, old_sha, new_sha)
            if key in cache:
                entry = cache[key]
                verdicts.append(
                    Verdict(
                        display=display,
                        change=change,
                        risk=entry.get("risk", "medium"),
                        summary=entry.get("summary", ""),
                        findings=entry.get("findings", []),
                        kind="audit",
                    )
                )
                cache_hits += 1
                print(f"  cache hit ({key})", file=sys.stderr)
                continue

            new_tar = download_tarball(change.owner, change.repo, new_sha, tmp_path, gh_token)
            if FETCH_DELAY:
                time.sleep(FETCH_DELAY)
            if not new_tar:
                verdicts.append(
                    Verdict(
                        display=display,
                        change=change,
                        risk="high",
                        summary=(
                            f"Could not download tarball for {change.owner}/"
                            f"{change.repo}@{new_sha}. Manual review required."
                        ),
                        findings=[],
                        kind="audit",
                    )
                )
                continue
            new_extract = tmp_path / f"new-{change.owner}-{change.repo}-{new_sha}"
            new_extract.mkdir()
            new_dir = extract_tarball(new_tar, new_extract)
            if not new_dir:
                verdicts.append(
                    Verdict(
                        display=display,
                        change=change,
                        risk="high",
                        summary="Could not extract new tarball. Manual review required.",
                        findings=[],
                        kind="audit",
                    )
                )
                continue

            old_dir = None
            if old_sha:
                old_tar = download_tarball(
                    change.owner, change.repo, old_sha, tmp_path, gh_token
                )
                if FETCH_DELAY:
                    time.sleep(FETCH_DELAY)
                if old_tar:
                    old_extract = tmp_path / f"old-{change.owner}-{change.repo}-{old_sha}"
                    old_extract.mkdir()
                    old_dir = extract_tarball(old_tar, old_extract)

            diff_text = diff_trees(old_dir, new_dir)
            if not diff_text.strip():
                entry = {
                    "risk": "none",
                    "summary": "No source changes detected between refs.",
                    "findings": [],
                }
                cache[key] = entry
                verdicts.append(
                    Verdict(display=display, change=change, kind="audit", **entry)
                )
                continue

            verdict_data = call_claude(
                display=display,
                old_ref=change.old_ref,
                new_ref=change.new_ref,
                kind=change.kind,
                diff_text=diff_text,
                api_key=api_key,
                model=model,
            )
            entry = {
                "risk": verdict_data.get("risk", "medium"),
                "summary": verdict_data.get("summary", "No summary provided."),
                "findings": verdict_data.get("findings", []),
            }
            # Only cache real Claude verdicts; transient errors should retry.
            if "Audit failed" not in entry["summary"]:
                cache[key] = entry
            verdicts.append(
                Verdict(display=display, change=change, kind="audit", **entry)
            )

    save_verdict_cache(cache_path, cache)
    if cache_path:
        print(
            f"Verdict cache: {cache_hits}/{len(changes)} hits; "
            f"{len(cache)} total entries stored.",
            file=sys.stderr,
        )

    if not verdicts:
        print("No actionable findings.", file=sys.stderr)
        return 0

    print(format_comment(verdicts))

    has_critical = any(v.risk == "critical" for v in verdicts)
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
