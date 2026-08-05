#!/usr/bin/env python3
"""Validate public client artifacts and sanitized source exports."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

_PUBLIC_VERIFIER_PATH = Path(__file__).with_name("verify-public-artifacts.py")
_PUBLIC_SPEC = importlib.util.spec_from_file_location("verify_public_artifacts", _PUBLIC_VERIFIER_PATH)
if _PUBLIC_SPEC is None or _PUBLIC_SPEC.loader is None:
    raise RuntimeError(f"cannot load public artifact verifier: {_PUBLIC_VERIFIER_PATH}")
_public = importlib.util.module_from_spec(_PUBLIC_SPEC)
_PUBLIC_SPEC.loader.exec_module(_public)
VerificationError = _public.VerificationError
fail = _public.fail
verify_python_package = _public.verify_python_package
verify_npm_package = _public.verify_npm_package
verify_dist_entries = _public.verify_dist_entries
archive_members = _public.archive_members
requirement_covers_major = _public.requirement_covers_major

ROOT = Path(__file__).resolve().parent.parent
PRIVATE_INTERNAL_MARKER_POLICY = Path(
    os.environ.get("PUBLIC_CLIENT_INTERNAL_MARKERS_FILE", ROOT / ".gitlab/security/public-client-internal-markers.txt")
)
CANONICAL_DOCUMENTATION_URLS = {
    "python": "https://crimsoncrawler.com/docs/clients/python-client/",
    "typescript": "https://crimsoncrawler.com/docs/clients/typescript-client/",
    "cli": "https://crimsoncrawler.com/docs/clients/cli/",
    "docs": "https://crimsoncrawler.com/docs/introduction/",
    "mcp": "https://crimsoncrawler.com/docs/clients/mcp/",
}
FORBIDDEN_PNG_METADATA_CHUNKS = {b"eXIf", b"iTXt", b"tEXt", b"tIME", b"zTXt"}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
# The spider mark is identical in every repository; the wordmark is not — each carries that
# repository's product glyph, so its digest is pinned per kind. Both are still exact-match pinned:
# an export may only ship brand art that came from portal/public/.
CANONICAL_SPIDER_SHA256 = "d25864a14deb269490c01832bc7ed92a6d2134bdaa6b779822b6937cc4324e0c"
CANONICAL_WORDMARK_SHA256 = {
    "python": "bfa605463d55abcd60670e50bd773bde72c8606466e442490bb81405ce66f934",
    "typescript": "cfd25573bc9ea7accc5766e5f9806804e8079b6043f79a86b9992e03d9865aaf",
    "cli": "8137afe49c6ada2d8c67315f03ca21b69f12931a205f1ecb49b50ab5e27f1b8c",
    "docs": "866f37a3fdc8ca6c3abbe0464858d8b29614cbcda8457fafcdef145444301a26",
    "mcp": "b4aecff5e6c01ba3600c60d25b86fe49bec94b87250564c1731fafdf9fa60fd9",
}


def policy_lines(path: Path) -> tuple[bytes, ...]:
    return tuple(
        line for raw_line in path.read_bytes().splitlines() if (line := raw_line.strip()) and not line.startswith(b"#")
    )


def internal_marker_policy() -> tuple[bytes, ...]:
    if not PRIVATE_INTERNAL_MARKER_POLICY.is_file():
        return ()
    markers = policy_lines(PRIVATE_INTERNAL_MARKER_POLICY)
    if not markers:
        fail("internal marker policy contains no markers")
    return markers


def scan_content(location: str, content: bytes) -> None:
    _public.scan_content(location, content)
    lowered = content.lower()
    for marker in internal_marker_policy():
        if marker.lower() in lowered:
            fail(f"{location}: internal-only text present")


def verify_brand_asset_metadata(directory: Path, kind: str) -> None:
    png = (directory / "assets/spider.png").read_bytes()
    if not png.startswith(PNG_SIGNATURE):
        fail(f"{directory}: spider.png is not a PNG")
    offset = len(PNG_SIGNATURE)
    saw_end = False
    while offset < len(png):
        if offset + 12 > len(png):
            fail(f"{directory}: spider.png has a malformed chunk")
        length = int.from_bytes(png[offset : offset + 4], "big")
        chunk_type = png[offset + 4 : offset + 8]
        offset += 12 + length
        if offset > len(png):
            fail(f"{directory}: spider.png has a malformed chunk")
        if chunk_type in FORBIDDEN_PNG_METADATA_CHUNKS:
            fail(f"{directory}: forbidden PNG metadata chunk {chunk_type.decode('ascii')}")
        if chunk_type == b"IEND":
            saw_end = True
            break
    if not saw_end or offset != len(png):
        fail(f"{directory}: spider.png has trailing or missing data")

    svg_path = directory / "assets/crimson-crawler-logo.svg"
    svg = svg_path.read_bytes().lower()
    if b"<metadata" in svg or b"<!--" in svg:
        fail(f"{directory}: forbidden SVG metadata")
    expected_wordmark = CANONICAL_WORDMARK_SHA256.get(kind)
    if expected_wordmark is None:
        fail(f"{directory}: no canonical wordmark pinned for kind: {kind}")
    pinned = {
        "assets/spider.png": CANONICAL_SPIDER_SHA256,
        "assets/crimson-crawler-logo.svg": expected_wordmark,
    }
    for relative, expected in pinned.items():
        actual = hashlib.sha256((directory / relative).read_bytes()).hexdigest()
        if actual != expected:
            fail(f"{directory}: canonical brand asset content mismatch: {relative}")


def reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def verify_mcp_source(directory: Path) -> None:
    expected_metadata = {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": "com.crimsoncrawler/mcp-server",
        "title": "Crimson Crawler",
        "description": "Enrich, search, assess, and manage threat intelligence through 80+ typed MCP tools.",
        "websiteUrl": "https://crimsoncrawler.com/docs/clients/mcp/",
        "remotes": [
            {
                "type": "streamable-http",
                "url": "https://crimsoncrawler.com/mcp/v1",
                "headers": [
                    {
                        "name": "apikey",
                        "description": "Your Crimson Crawler API key",
                        "isRequired": True,
                        "isSecret": True,
                    }
                ],
            }
        ],
    }
    try:
        metadata = json.loads(
            (directory / "server.json").read_text(),
            object_pairs_hook=reject_duplicate_json_keys,
        )
        example_path = directory / "examples/mcp.example.json"
        example = json.loads(example_path.read_text(), object_pairs_hook=reject_duplicate_json_keys)
        readme = (directory / "README.md").read_text()
        ignored_files = set((directory / ".gitignore").read_text().splitlines())
    except (json.JSONDecodeError, OSError, ValueError) as error:
        fail(f"{directory}: invalid MCP public metadata: {error}")

    version = metadata.pop("version", None)
    if not isinstance(version, str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        fail(f"{directory}: server.json must contain a semantic version")
    if metadata != expected_metadata:
        fail(f"{directory}: server.json does not match the public MCP contract")
    if f"version `{version}`" not in readme:
        fail(f"{directory}: README.md version does not match server.json")
    if not {".mcp.json", "mcp.local.json"} <= ignored_files:
        fail(f"{directory}: MCP local credential files must be ignored")

    expected_example = {
        "mcpServers": {
            "crimson-crawler": {
                "type": "http",
                "url": "https://crimsoncrawler.com/mcp/v1",
                "headers": {"apikey": "your-api-key-here"},
            }
        }
    }
    if example != expected_example:
        fail(f"{directory}: examples/mcp.example.json must contain only the public placeholder contract")


def source_contract(kind: str) -> tuple[set[str], set[str]]:
    contracts = {
        "python": (
            {
                ".github/workflows/release.yml",
                ".github/workflows/ci.yml",
                "CONTRIBUTING.md",
                "LICENSE",
                "README.md",
                "SECURITY.md",
                "assets/crimson-crawler-logo.svg",
                "assets/spider.png",
                "hatch_build.py",
                "openapi.snapshot.json",
                "openapi_python_client_config.yaml",
                "pyproject.toml",
                "scripts/check-public-client-registry.py",
                "scripts/generate-public-sbom.py",
                "scripts/normalize-public-sbom.py",
                "scripts/codegen.py",
                "scripts/verify-public-artifacts.py",
                "src/crimson_crawler_client/_generated",
                "src",
                "tests",
                "uv.lock",
            },
            {
                ".gitignore",
                ".github",
                "CONTRIBUTING.md",
                "LICENSE",
                "README.md",
                "SECURITY.md",
                "assets",
                "hatch_build.py",
                "openapi.snapshot.json",
                "openapi_python_client_config.yaml",
                "pyproject.toml",
                "scripts",
                "src",
                "tests",
                "uv.lock",
            },
        ),
        "typescript": (
            {
                ".github/workflows/release.yml",
                ".github/workflows/ci.yml",
                "CONTRIBUTING.md",
                "LICENSE",
                "README.md",
                "SECURITY.md",
                "assets/crimson-crawler-logo.svg",
                "assets/spider.png",
                "openapi-ts.config.ts",
                "openapi.snapshot.json",
                "package-lock.json",
                "package.json",
                "scripts/check-public-client-registry.py",
                "scripts/generate-public-sbom.py",
                "scripts/normalize-public-sbom.py",
                "scripts/codegen.mjs",
                "scripts/verify-public-artifacts.py",
                "src",
                "tests",
                "tsconfig.json",
                "tsconfig.test.json",
                "tsup.config.ts",
                "vitest.config.ts",
            },
            {
                ".gitignore",
                ".github",
                "CONTRIBUTING.md",
                "LICENSE",
                "README.md",
                "SECURITY.md",
                "assets",
                "eslint.config.js",
                "openapi-ts.config.ts",
                "openapi.snapshot.json",
                "package-lock.json",
                "package.json",
                "scripts",
                "src",
                "tests",
                "tsconfig.json",
                "tsconfig.test.json",
                "tsup.config.ts",
                "vitest.config.ts",
            },
        ),
        "cli": (
            {
                ".github/workflows/release.yml",
                ".github/workflows/ci.yml",
                "CONTRIBUTING.md",
                "LICENSE",
                "README.md",
                "SECURITY.md",
                "assets/crimson-crawler-logo.svg",
                "assets/spider.png",
                "hatch_build.py",
                "pyproject.toml",
                "scripts/check-public-client-registry.py",
                "scripts/generate-public-sbom.py",
                "scripts/normalize-public-sbom.py",
                "scripts/verify-public-artifacts.py",
                "src",
                "tests",
                "uv.lock",
            },
            {
                ".gitignore",
                "CONTRIBUTING.md",
                ".github",
                "LICENSE",
                "README.md",
                "SECURITY.md",
                "assets",
                "hatch_build.py",
                "examples",
                "pyproject.toml",
                "scripts",
                "src",
                "tests",
                "uv.lock",
            },
        ),
        "docs": (
            {
                ".github/workflows/release.yml",
                "CONTRIBUTING.md",
                "LICENSE",
                "README.md",
                "SECURITY.md",
                "assets/crimson-crawler-logo.svg",
                "assets/spider.png",
                "docs",
            },
            {".gitignore", ".github", "CONTRIBUTING.md", "LICENSE", "README.md", "SECURITY.md", "assets", "docs"},
        ),
        "mcp": (
            {
                ".github/workflows/release.yml",
                "CONTRIBUTING.md",
                "LICENSE",
                "README.md",
                "SECURITY.md",
                "assets/crimson-crawler-logo.svg",
                "assets/spider.png",
                "examples/mcp.example.json",
                "scripts/verify-client-artifacts.py",
                "scripts/verify-public-artifacts.py",
                "server.json",
            },
            {
                ".gitignore",
                ".github",
                "CONTRIBUTING.md",
                "LICENSE",
                "README.md",
                "SECURITY.md",
                "assets",
                "examples",
                "scripts",
                "server.json",
            },
        ),
    }
    try:
        return contracts[kind]
    except KeyError:
        fail(f"unknown public source kind: {kind}")


def verify_source_export(directory: Path, kind: str) -> None:
    required, allowed_roots = source_contract(kind)
    required |= {
        ".github/CODEOWNERS",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/pull_request_template.md",
        "CODE_OF_CONDUCT.md",
        "NOTICE",
    }
    allowed_roots |= {"CODE_OF_CONDUCT.md", "NOTICE"}
    if kind == "docs":
        required.add("scripts/prepare-public-docs.py")
        allowed_roots.add("scripts")
    # The three code exports ship `ci.yml`, whose secret-scan job reads its policy from
    # the repository root. Require the file here so a missing export step fails the gate
    # instead of publishing a workflow that references a config the tree never carried.
    if kind in {"python", "typescript", "cli"}:
        required.add(".gitleaks.toml")
        allowed_roots.add(".gitleaks.toml")
    # The shipped copy of this script runs against a *checked-out* public repository, not an
    # export directory — `mcp-server.yml` invokes `--source . --source-kind mcp` right after
    # `actions/checkout`. So `.git` is present there and absent here, which failed every
    # mcp-server release with `unexpected mcp source roots: .git`. Tolerate the directory and
    # never descend into it. Nothing is lost: git cannot commit a nested `.git`, so the entry
    # in `forbidden_source_parts` was guarding a state git itself makes unreachable.
    allowed_roots.add(".git")
    missing = sorted(item for item in required if not (directory / item).exists())
    if missing:
        fail(f"{directory}: {kind} source export is incomplete: {', '.join(missing)}")

    readme = (directory / "README.md").read_text()
    documentation_url = CANONICAL_DOCUMENTATION_URLS[kind]
    if documentation_url not in readme:
        fail(f"{directory}: {kind} README must link to canonical documentation: {documentation_url}")

    # Every repository references the brand art it ships, so a tree renders on GitHub with nothing
    # deployed and carries no dependency on the portal being up. The docs site mirrors the three package
    # READMEs from /docs/clients/, where a relative path cannot resolve, so
    # portal/scripts/sync-client-readmes.mjs rewrites these two paths to portal/public/ when it copies
    # them. Enforced in both directions because it has been flipped the wrong way more than once.
    for reference in ('src="assets/spider.png"', 'src="assets/crimson-crawler-logo.svg"'):
        if reference not in readme:
            fail(f"{directory}: {kind} README must reference its shipped brand asset: {reference}")
    if "crimsoncrawler.com/logo-icon.png" in readme or "crimsoncrawler.com/crimson-crawler-logo" in readme:
        fail(f"{directory}: {kind} README ships its brand assets and must not fetch them over the network")

    unexpected = sorted(item.name for item in directory.iterdir() if item.name not in allowed_roots)
    if unexpected:
        fail(f"{directory}: unexpected {kind} source roots: {', '.join(unexpected)}")

    forbidden_source_parts = {".env", ".git", ".npmrc", "__pycache__", "dist", "node_modules"}
    for path in directory.rglob("*"):
        # Skip the checkout's own VCS metadata rather than scanning it — see `allowed_roots`
        # above. Its contents are not shipped source, and packfiles are not text to scan.
        if ".git" in path.relative_to(directory).parts:
            continue
        if path.is_symlink():
            fail(f"{directory}: symlink is not allowed: {path.relative_to(directory)}")
        if not path.is_file():
            continue
        relative = path.relative_to(directory)
        if set(relative.parts) & forbidden_source_parts:
            fail(f"{directory}: forbidden source export path: {relative}")
        if relative.suffix == ".map":
            fail(f"{directory}: source map is not allowed: {relative}")
        scan_content(str(relative), path.read_bytes())
    verify_brand_asset_metadata(directory, kind)

    workflow_files = {
        path.relative_to(directory).as_posix() for path in (directory / ".github").rglob("*") if path.is_file()
    }
    expected_github_files = {
        ".github/CODEOWNERS",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/pull_request_template.md",
        ".github/workflows/release.yml",
    }
    if kind in {"python", "typescript", "cli"}:
        expected_github_files.add(".github/workflows/ci.yml")
    if kind == "python":
        # One-time incident recovery for v4.1.0. `workflow_dispatch` only resolves against
        # the default branch, so the file must ship. Enumerated here rather than merely
        # tolerated, so it cannot appear in any other export by accident.
        expected_github_files.add(".github/workflows/recover-release.yml")
    if workflow_files != expected_github_files:
        fail(f"{directory}: .github contents do not match the public repository contract")

    if kind == "mcp":
        verify_mcp_source(directory)
        return

    if kind != "docs":
        return
    docs = [path for path in (directory / "docs").rglob("*") if path.is_file()]
    if not docs:
        fail(f"{directory}: docs must contain at least one Markdown file")
    for path in docs:
        relative = path.relative_to(directory)
        if path.suffix != ".md":
            fail(f"{directory}: docs may contain only Markdown files: {relative}")
        if not path.read_bytes().strip():
            fail(f"{directory}: empty documentation file: {relative}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--py-only", action="store_true")
    parser.add_argument("--ts-only", action="store_true")
    parser.add_argument("--cli-only", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--source-kind", choices=("python", "typescript", "cli", "docs", "mcp"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    selected = sum((args.py_only, args.ts_only, args.cli_only, args.source is not None))
    if selected > 1:
        fail("artifact filters and --source are mutually exclusive")
    if args.source is not None:
        if args.source_kind is None:
            fail("--source-kind is required with --source")
        verify_source_export(args.source.resolve(), args.source_kind)
    elif args.source_kind is not None:
        fail("--source-kind requires --source")
    else:
        if args.py_only or selected == 0:
            verify_python_package(ROOT / "client-py", "crimson-crawler-client")
        if args.ts_only or selected == 0:
            verify_npm_package(ROOT / "client-ts")
        if args.cli_only or selected == 0:
            verify_python_package(ROOT / "client-cli", "crimson-crawler-cli", cli=True)
    print("Client release input verified.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
