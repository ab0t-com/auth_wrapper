"""Supply-chain guard: the published docs of this repo must not tell anyone to install a package name we do not own.

Why: PyPI `ab0t-auth` is not registered by us (anyone can publish under it), and the npm `@authmesh` scope belongs to an
unrelated third party. A README line such as `pip install ab0t-auth` or `npm install @authmesh/sdk` would install a
stranger's code. The supported install is the git form:

    pip install "ab0t-auth @ git+https://github.com/ab0t-com/auth_wrapper.git@v0.1.4"

The browser SDK is not on npm; it is served by the auth service:
    <script src="https://auth.service.ab0t.com/login/_static/authmesh.global.js"></script>

Scope: every doc file that ships in the public repo (README*, CONTRIBUTING, CHANGELOG, docs/, Skills/, migrations/, demo/).
Not scanned: src/, scripts/, tests/ (code, not docs) and gitignored internal dirs (tickets/, .archive*/).
Ticket: auth/output/tickets/20261016_docs_install_packages_we_do_not_own/ (monorepo).
"""
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

_SAME_CMD = r"[^\n;|&]*?"
RULES = [
    ("npm-scope-not-ours",
     re.compile(r"\b(?:npm\s+(?:i|install|add)|yarn\s+add|pnpm\s+(?:add|i|install)|bun\s+add)\b"
                + _SAME_CMD + r"@(?:authmesh|auth-service)/")),
    ("import-from-npm-scope-not-ours",
     re.compile(r"(?:\bfrom\s*|\brequire\(\s*)['\"]@(?:authmesh|auth-service)/")),
    ("pypi-ab0t-auth-without-git",
     re.compile(r"\bpip3?\s+install\b" + _SAME_CMD
                + r"(?<![\w-])ab0t-auth(?![\w-])(?!(?:\[[^\]\s]*\])?['\"]?\s*@\s*git\+)")),
    ("pypi-auth-service-sdk",
     re.compile(r"\bpip3?\s+install\b" + _SAME_CMD + r"(?<![\w-])auth-service-sdk(?![\w-])")),
    ("pypi-authmesh",
     re.compile(r"\bpip3?\s+install\b" + _SAME_CMD + r"(?<![\w./-])authmesh[\w-]*")),
]

DOC_EXT = {".md", ".markdown", ".txt", ".rst", ".html"}
DOC_DIRS = ["docs", "Skills", "migrations", "demo"]


def _doc_files():
    files = [p for p in REPO.iterdir() if p.is_file() and p.suffix.lower() in DOC_EXT]
    for d in DOC_DIRS:
        root = REPO / d
        if root.is_dir():
            files += [p for p in root.rglob("*")
                      if p.is_file() and p.suffix.lower() in DOC_EXT
                      and not any(part.startswith(".archive") or part in {"tickets", "node_modules"}
                                  for part in p.relative_to(REPO).parts)]
    # Root-level internal files are gitignored (tasklist*.md, work_log*.md, *_security_audit.md ...): skip them.
    skip = re.compile(r"^(tasklist.*|work_log.*|.*_security_audit|SECURITY_REVIEW.*|RELEASE_PLAN.*|ISSUE-.*)\.md$")
    return sorted(p for p in files if not skip.match(p.name))


def _hits():
    out = []
    for p in _doc_files():
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for name, rx in RULES:
                if rx.search(line):
                    out.append(f"{p.relative_to(REPO)}:{n}: [{name}] {line.strip()[:160]}")
    return out


def test_scans_the_readme():
    assert REPO / "README.md" in _doc_files()


@pytest.mark.parametrize("bad", [
    "pip install ab0t-auth", 'pip install "ab0t-auth[dev]"', "pip install ab0t-auth[fastapi]",
    'pip install "ab0t-auth==0.1.4"', "npm install @authmesh/sdk", "yarn add @authmesh/sdk",
    "import { AuthMeshClient } from '@authmesh/sdk';", "pip install auth-service-sdk",
])
def test_rule_catches(bad):
    assert any(rx.search(bad) for _, rx in RULES), bad


@pytest.mark.parametrize("good", [
    'pip install "ab0t-auth @ git+https://github.com/ab0t-com/auth_wrapper.git@v0.1.4"',
    'pip install "ab0t-auth[dev] @ git+https://github.com/ab0t-com/auth_wrapper.git@v0.1.4"',
    '<script src="https://auth.service.ab0t.com/login/_static/authmesh.global.js"></script>',
    "`@authmesh/sdk` 0.4.1 refreshes 30 s early",
])
def test_rule_passes(good):
    assert not any(rx.search(good) for _, rx in RULES), good


def test_public_docs_have_no_install_line_for_a_name_we_do_not_own():
    hits = _hits()
    assert not hits, (f"{len(hits)} install line(s) for package names we do not own:\n" + "\n".join(hits)
                      + '\nUse: pip install "ab0t-auth @ git+https://github.com/ab0t-com/auth_wrapper.git@v0.1.4"')
