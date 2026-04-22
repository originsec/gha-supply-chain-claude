"""Unit tests for audit-supply-chain.py."""

from __future__ import annotations

import importlib
import json
import re
import sys
import tarfile
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

audit = importlib.import_module("audit-supply-chain")

UsesRef = audit.UsesRef
RefChange = audit.RefChange
Verdict = audit.Verdict
parse_uses_value = audit.parse_uses_value
extract_uses_refs = audit.extract_uses_refs
is_relevant_yaml = audit.is_relevant_yaml
classify_changes = audit.classify_changes
pinning_verdict_for = audit.pinning_verdict_for
docker_verdict_for = audit.docker_verdict_for
extract_tarball = audit.extract_tarball
diff_trees = audit.diff_trees
collect_files = audit.collect_files
format_comment = audit.format_comment
SHA_PIN_RE = audit.SHA_PIN_RE


# ---------------------------------------------------------------------------
# parse_uses_value
# ---------------------------------------------------------------------------


class TestParseUsesValue:
    def test_standard_action(self):
        r = parse_uses_value("actions/checkout@v4", "wf.yml")
        assert r is not None
        assert r.owner == "actions"
        assert r.repo == "checkout"
        assert r.subpath == ""
        assert r.ref == "v4"
        assert r.kind == "action"

    def test_sha_pinned(self):
        sha = "0123456789abcdef0123456789abcdef01234567"
        r = parse_uses_value(f"actions/checkout@{sha}", "wf.yml")
        assert r is not None
        assert r.is_sha_pinned()
        assert r.ref == sha

    def test_action_in_subdir(self):
        r = parse_uses_value("aws-actions/amazon-ecs@v1/deploy", "wf.yml")
        # subpath is joined from segments past the second one
        assert r is not None
        # owner/repo always first two; remaining joined as subpath
        assert r.owner == "aws-actions"
        assert r.repo == "amazon-ecs"
        # Note: the form above is non-standard — but our parser accepts it
        # and treats any segment past the repo as subpath. A more common form
        # is tested below (reusable workflow).

    def test_reusable_workflow(self):
        r = parse_uses_value(
            "octo-org/reusable/.github/workflows/ci.yml@main", "caller.yml"
        )
        assert r is not None
        assert r.owner == "octo-org"
        assert r.repo == "reusable"
        assert r.subpath == ".github/workflows/ci.yml"
        assert r.kind == "reusable-workflow"

    def test_local_action_skipped(self):
        assert parse_uses_value("./.github/actions/my-local", "wf.yml") is None
        assert parse_uses_value("../shared/action", "wf.yml") is None
        assert parse_uses_value(".", "wf.yml") is None

    def test_docker_tag(self):
        r = parse_uses_value("docker://alpine:3.18", "wf.yml")
        assert r is not None
        assert r.kind == "docker"
        assert r.subpath == "alpine:3.18"

    def test_docker_digest(self):
        r = parse_uses_value(
            "docker://alpine@sha256:deadbeef" + "c" * 56, "wf.yml"
        )
        assert r is not None
        assert r.kind == "docker"
        assert "@sha256:" in r.subpath

    def test_missing_ref(self):
        # owner/repo with no @ref is ambiguous — we skip it
        assert parse_uses_value("actions/checkout", "wf.yml") is None
        assert parse_uses_value("actions/checkout@", "wf.yml") is None

    def test_single_segment(self):
        assert parse_uses_value("foo@v1", "wf.yml") is None


# ---------------------------------------------------------------------------
# extract_uses_refs
# ---------------------------------------------------------------------------


class TestExtractUsesRefs:
    def test_workflow_file(self):
        text = textwrap.dedent("""\
            name: CI
            on: [push]
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: 'actions/setup-node@v3'
                  - name: lint
                    run: npm ci
                  - uses: "super-linter/super-linter@v5.0.0"  # linter
        """)
        refs = extract_uses_refs(text, "ci.yml")
        assert [r.display for r in refs] == [
            "actions/checkout@v4",
            "actions/setup-node@v3",
            "super-linter/super-linter@v5.0.0",
        ]

    def test_reusable_workflow_at_job_level(self):
        text = textwrap.dedent("""\
            jobs:
              call-shared:
                uses: org/shared/.github/workflows/build.yml@v2
                with:
                  env: prod
        """)
        refs = extract_uses_refs(text, "wf.yml")
        assert len(refs) == 1
        assert refs[0].kind == "reusable-workflow"
        assert refs[0].subpath == ".github/workflows/build.yml"

    def test_commented_out_uses(self):
        text = textwrap.dedent("""\
            jobs:
              build:
                steps:
                  # - uses: actions/stale@v1  # disabled for now
                  - uses: actions/checkout@v4
        """)
        refs = extract_uses_refs(text, "wf.yml")
        assert [r.display for r in refs] == ["actions/checkout@v4"]

    def test_inline_comment_stripped(self):
        text = "      - uses: actions/checkout@v4  # pinned later\n"
        refs = extract_uses_refs(text, "wf.yml")
        assert len(refs) == 1
        assert refs[0].ref == "v4"

    def test_composite_action_yml(self):
        text = textwrap.dedent("""\
            name: My composite
            runs:
              using: composite
              steps:
                - uses: actions/checkout@v4
                - run: echo hi
                  shell: bash
                - uses: actions/cache@v3
        """)
        refs = extract_uses_refs(text, "action.yml")
        assert len(refs) == 2
        assert refs[0].repo == "checkout"
        assert refs[1].repo == "cache"


# ---------------------------------------------------------------------------
# is_relevant_yaml
# ---------------------------------------------------------------------------


class TestIsRelevantYaml:
    def test_workflow_paths(self):
        assert is_relevant_yaml(".github/workflows/ci.yml")
        assert is_relevant_yaml(".github/workflows/ci.yaml")
        assert is_relevant_yaml("sub/.github/workflows/sub-ci.yml")

    def test_action_yml(self):
        assert is_relevant_yaml("action.yml")
        assert is_relevant_yaml("action.yaml")
        assert is_relevant_yaml("nested/path/action.yml")

    def test_irrelevant(self):
        assert not is_relevant_yaml("README.md")
        assert not is_relevant_yaml(".github/dependabot.yml")
        assert not is_relevant_yaml("src/foo.yml")
        assert not is_relevant_yaml(".github/workflows-archive/old.yml")


# ---------------------------------------------------------------------------
# classify_changes
# ---------------------------------------------------------------------------


def _ref(owner: str, repo: str, ref: str, *, subpath: str = "", kind: str = "action", file: str = "wf.yml") -> UsesRef:
    return UsesRef(
        owner=owner, repo=repo, subpath=subpath, ref=ref, file_path=file, kind=kind
    )


class TestClassifyChanges:
    def test_no_change(self):
        base = [_ref("actions", "checkout", "v4")]
        head = [_ref("actions", "checkout", "v4")]
        assert classify_changes(base, head) == []

    def test_new_dependency(self):
        base: list[UsesRef] = []
        head = [_ref("actions", "checkout", "v4")]
        changes = classify_changes(base, head)
        assert len(changes) == 1
        assert changes[0].old_ref is None
        assert changes[0].new_ref == "v4"

    def test_removed_dependency_ignored(self):
        base = [_ref("actions", "stale", "v1")]
        head: list[UsesRef] = []
        assert classify_changes(base, head) == []

    def test_ref_bump(self):
        base = [_ref("actions", "checkout", "v3")]
        head = [_ref("actions", "checkout", "v4")]
        changes = classify_changes(base, head)
        assert len(changes) == 1
        assert changes[0].old_ref == "v3"
        assert changes[0].new_ref == "v4"

    def test_same_action_multiple_files(self):
        # Same (owner, repo) used in two files, both bump to v4
        base = [
            _ref("actions", "checkout", "v3", file="a.yml"),
            _ref("actions", "checkout", "v3", file="b.yml"),
        ]
        head = [
            _ref("actions", "checkout", "v4", file="a.yml"),
            _ref("actions", "checkout", "v4", file="b.yml"),
        ]
        changes = classify_changes(base, head)
        assert len(changes) == 1  # deduped by (owner, repo, subpath)

    def test_docker_and_local_skipped(self):
        head = [
            _ref("", "", "", subpath="alpine:3", kind="docker"),
            _ref("actions", "checkout", "v4"),
        ]
        changes = classify_changes([], head)
        assert len(changes) == 1
        assert changes[0].owner == "actions"

    def test_reusable_workflow_classified(self):
        base = [
            _ref(
                "org",
                "shared",
                "v1",
                subpath=".github/workflows/ci.yml",
                kind="reusable-workflow",
            )
        ]
        head = [
            _ref(
                "org",
                "shared",
                "v2",
                subpath=".github/workflows/ci.yml",
                kind="reusable-workflow",
            )
        ]
        changes = classify_changes(base, head)
        assert len(changes) == 1
        assert changes[0].kind == "reusable-workflow"
        assert changes[0].subpath == ".github/workflows/ci.yml"


# ---------------------------------------------------------------------------
# Pinning findings
# ---------------------------------------------------------------------------


class TestPinningVerdict:
    def _change(self, ref: str) -> RefChange:
        return RefChange(
            owner="actions",
            repo="checkout",
            subpath="",
            old_ref=None,
            new_ref=ref,
            kind="action",
        )

    def test_sha_pin_passes(self):
        sha = "0" * 40
        assert pinning_verdict_for(self._change(sha)) is None

    def test_tag_is_medium(self):
        v = pinning_verdict_for(self._change("v4"))
        assert v is not None
        assert v.risk == "medium"

    def test_semver_tag_is_medium(self):
        v = pinning_verdict_for(self._change("v4.1.0"))
        assert v is not None
        assert v.risk == "medium"

    def test_main_is_high(self):
        v = pinning_verdict_for(self._change("main"))
        assert v is not None
        assert v.risk == "high"

    def test_master_is_high(self):
        v = pinning_verdict_for(self._change("master"))
        assert v is not None
        assert v.risk == "high"

    def test_partial_sha_is_medium(self):
        # 12-char SHA is NOT a full pin even though it's commit-looking
        v = pinning_verdict_for(self._change("abc123def456"))
        assert v is not None
        assert v.risk == "medium"


class TestSHAPinRegex:
    def test_full_sha(self):
        assert SHA_PIN_RE.match("0123456789abcdef0123456789abcdef01234567")

    def test_uppercase_rejected(self):
        assert not SHA_PIN_RE.match("0123456789ABCDEF0123456789abcdef01234567")

    def test_short_sha_rejected(self):
        assert not SHA_PIN_RE.match("0123456789ab")

    def test_tag_rejected(self):
        assert not SHA_PIN_RE.match("v4")
        assert not SHA_PIN_RE.match("main")


# ---------------------------------------------------------------------------
# Docker findings
# ---------------------------------------------------------------------------


class TestDockerVerdict:
    def test_digest_pinned_is_low(self):
        uses = UsesRef(
            owner="",
            repo="",
            subpath="alpine@sha256:" + "a" * 64,
            ref="",
            file_path="wf.yml",
            kind="docker",
        )
        v = docker_verdict_for(uses)
        assert v.risk == "low"

    def test_tag_is_medium(self):
        uses = UsesRef(
            owner="",
            repo="",
            subpath="alpine:3.18",
            ref="",
            file_path="wf.yml",
            kind="docker",
        )
        v = docker_verdict_for(uses)
        assert v.risk == "medium"


# ---------------------------------------------------------------------------
# collect_files, diff_trees, extract_tarball
# ---------------------------------------------------------------------------


class TestCollectFiles:
    def test_empty_dir(self, tmp_path):
        assert collect_files(tmp_path) == {}

    def test_none_dir(self):
        assert collect_files(None) == {}

    def test_forward_slashes(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "b.txt").write_text("x")
        result = collect_files(tmp_path)
        assert "a/b.txt" in result


class TestDiffTrees:
    def test_identical(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "f").write_text("hello\n")
        (new / "f").write_text("hello\n")
        assert diff_trees(old, new).strip() == ""

    def test_added_file(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (new / "added.js").write_text("console.log('x')\n")
        result = diff_trees(old, new)
        assert "+console.log('x')" in result

    def test_new_dep_none_old(self, tmp_path):
        new = tmp_path / "new"
        new.mkdir()
        (new / "action.yml").write_text("name: x\n")
        result = diff_trees(None, new)
        assert "+name: x" in result


class TestExtractTarball:
    def test_valid(self, tmp_path):
        inner = tmp_path / "pkg-abc"
        inner.mkdir()
        (inner / "action.yml").write_text("name: test\n")
        (inner / "dist").mkdir()
        (inner / "dist" / "index.js").write_text("console.log('hi')\n")

        tarball = tmp_path / "src.tar.gz"
        with tarfile.open(tarball, "w:gz") as tf:
            tf.add(inner, arcname="owner-repo-abc")

        dest = tmp_path / "out"
        dest.mkdir()
        result = extract_tarball(tarball, dest)
        assert result is not None
        assert (result / "action.yml").exists()

    def test_invalid(self, tmp_path):
        tarball = tmp_path / "broken.tar.gz"
        tarball.write_bytes(b"not a tarball")
        dest = tmp_path / "out"
        dest.mkdir()
        assert extract_tarball(tarball, dest) is None


# ---------------------------------------------------------------------------
# format_comment
# ---------------------------------------------------------------------------


class TestFormatComment:
    def _audit_verdict(self, display: str, risk: str, summary: str = "OK") -> Verdict:
        return Verdict(
            display=display,
            change=None,
            risk=risk,
            summary=summary,
            findings=[],
            kind="audit",
        )

    def test_contains_header_and_transitivity_banner(self):
        v = self._audit_verdict("actions/checkout@v4", "none")
        out = format_comment([v])
        assert "## GitHub Actions Supply Chain Audit" in out
        assert "Transitive actions" in out

    def test_sorts_by_risk(self):
        vs = [
            self._audit_verdict("safe/a@v1", "none"),
            self._audit_verdict("danger/b@v1", "critical"),
            self._audit_verdict("warn/c@v1", "medium"),
        ]
        out = format_comment(vs)
        crit_pos = out.index("danger/b")
        med_pos = out.index("warn/c")
        none_pos = out.index("safe/a")
        assert crit_pos < med_pos < none_pos

    def test_pinning_label(self):
        v = Verdict(
            display="actions/checkout@v4",
            change=None,
            risk="medium",
            summary="Tag pin",
            findings=[],
            kind="pinning",
        )
        out = format_comment([v])
        assert "(pinning)" in out

    def test_docker_label(self):
        v = Verdict(
            display="docker://alpine:3",
            change=None,
            risk="medium",
            summary="Not digest pinned",
            findings=[],
            kind="docker",
        )
        out = format_comment([v])
        assert "(docker)" in out

    def test_truncation(self):
        v = self._audit_verdict("big/one@v1", "low", "x" * 70_000)
        out = format_comment([v])
        assert len(out) <= audit.MAX_COMMENT_CHARS
        assert "truncated" in out


# ---------------------------------------------------------------------------
# Claude response parsing (raw_decode)
# ---------------------------------------------------------------------------


class TestClaudeParsing:
    def _parse(self, raw: str) -> dict:
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```\w*\n?", "", text)
            text = re.sub(r"\n?```$", "", text)
            text = text.strip()
        parsed, _ = json.JSONDecoder().raw_decode(text)
        return parsed

    def test_plain_json(self):
        raw = '{"risk": "none", "summary": "OK", "findings": []}'
        assert self._parse(raw)["risk"] == "none"

    def test_json_with_trailing_prose(self):
        raw = (
            '{"risk": "low", "summary": "Routine.", "findings": []}\n\n'
            "The diff shows a minor version bump."
        )
        assert self._parse(raw)["risk"] == "low"

    def test_fenced_json(self):
        raw = '```json\n{"risk": "medium", "summary": "Check.", "findings": []}\n```'
        assert self._parse(raw)["risk"] == "medium"
