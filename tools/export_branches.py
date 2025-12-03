#!/usr/bin/env python3
import html
import os
import pathlib
import shutil
import subprocess
from typing import Iterable

# Repository root (this script is assumed to live in tools/export_branches.py)
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SITE_ROOT = REPO_ROOT / "site"
WORKTREES_ROOT = REPO_ROOT / ".worktrees"
BRANCHES_ROOT = SITE_ROOT / "branches"

# File extensions that will be treated as text and converted to HTML
TEXT_EXTENSIONS = {
    ".rs",
    ".toml",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
    ".lock",
    ".cfg",
    ".conf",
    ".c",
    ".h",
    ".S",
    ".sh",
}


def run(cmd: list[str]) -> None:
    """Run a command and fail hard on error."""
    subprocess.run(cmd, check=True)


def list_remote_branches() -> list[str]:
    """
    Return list of remote branch refs like 'origin/main', 'origin/gic', ...

    Exclude 'origin/HEAD'.
    """
    result = subprocess.check_output(
        ["git", "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"],
        text=True,
    )
    branches: list[str] = []
    for line in result.splitlines():
        name = line.strip()
        if not name or name == "origin/HEAD":
            continue
        branches.append(name)
    return branches


def html_wrap(title: str, body: str) -> str:
    """Wrap escaped body text in a minimal HTML document."""
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '<meta charset="utf-8">\n'
        f"<title>{html.escape(title)}</title>\n"
        "</head>\n"
        "<body>\n"
        "<pre>\n"
        f"{body}\n"
        "</pre>\n"
        "</body>\n"
        "</html>\n"
    )


def is_text_file(path: pathlib.Path) -> bool:
    """Decide whether to render this file as HTML based on its extension."""
    return path.suffix in TEXT_EXTENSIONS


def export_tree(src_root: pathlib.Path, dest_root: pathlib.Path) -> None:
    """
    Export a single branch worktree to dest_root.

    Text files are converted to *.html, other files are currently skipped.
    """
    for src_path in src_root.rglob("*"):
        if src_path.is_dir():
            continue

        rel = src_path.relative_to(src_root)

        if is_text_file(src_path):
            dest_file = dest_root / (str(rel) + ".html")
            dest_file.parent.mkdir(parents=True, exist_ok=True)

            with src_path.open("r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            escaped = html.escape(content)
            html_doc = html_wrap(str(rel), escaped)

            with dest_file.open("w", encoding="utf-8") as f:
                f.write(html_doc)
        else:
            # Non-text files are skipped. If you need them, copy instead:
            # dest_file = dest_root / rel
            # dest_file.parent.mkdir(parents=True, exist_ok=True)
            # shutil.copy2(src_path, dest_file)
            continue


def clean_worktrees() -> None:
    """Remove temporary worktree directory."""
    if WORKTREES_ROOT.exists():
        shutil.rmtree(WORKTREES_ROOT)


def clean_site() -> None:
    """Remove previous site output and create base directories."""
    if SITE_ROOT.exists():
        shutil.rmtree(SITE_ROOT)
    SITE_ROOT.mkdir(parents=True, exist_ok=True)
    BRANCHES_ROOT.mkdir(parents=True, exist_ok=True)


def add_worktree(ref: str, worktree_dir: pathlib.Path) -> None:
    """
    Create a git worktree at worktree_dir for given ref (e.g. 'origin/main').

    Existing directory is removed before creating the worktree.
    """
    if worktree_dir.exists():
        shutil.rmtree(worktree_dir)
    worktree_dir.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "worktree", "add", "--force", str(worktree_dir), ref])


def branch_name_from_ref(ref: str) -> str:
    """
    Convert 'origin/main' -> 'main', 'origin/feature/foo' -> 'feature/foo'.

    This name is used in the URL hierarchy under /branches/.
    """
    if ref.startswith("origin/"):
        return ref[len("origin/") :]
    return ref


def write_index(branch_refs: Iterable[str]) -> None:
    """Write the top-level index.html listing all branches."""
    lines = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        '<meta charset="utf-8">',
        "<title>Branches index</title>",
        "</head>",
        "<body>",
        "<h1>Branches</h1>",
        "<ul>",
    ]

    for ref in sorted(branch_refs):
        branch = branch_name_from_ref(ref)
        href = f"branches/{html.escape(branch)}/"
        lines.append(f'<li><a href="{href}">{html.escape(branch)}</a></li>')

    lines.extend(
        [
            "</ul>",
            "</body>",
            "</html>",
            "",
        ]
    )

    index_path = SITE_ROOT / "index.html"
    index_path.write_text("\n".join(lines), encoding="utf-8")


def write_branch_index(dest_root: pathlib.Path, branch: str) -> None:
    """Write index.html under dest_root listing all HTML files in the branch."""
    items: list[str] = []

    for file in sorted(dest_root.rglob("*.html")):
        rel = file.relative_to(dest_root)
        # Skip the branch index itself
        if rel == pathlib.Path("index.html"):
            continue

        href = rel.as_posix()
        items.append(
            f'<li><a href="{href}">{html.escape(str(rel))}</a></li>'
        )

    lines = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        '<meta charset="utf-8">',
        f"<title>{html.escape(branch)} branch</title>",
        "</head>",
        "<body>",
        f"<h1>Branch: {html.escape(branch)}</h1>",
        "<ul>",
        *items,
        "</ul>",
        "</body>",
        "</html>",
        "",
    ]

    index_path = dest_root / "index.html"
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    clean_site()
    clean_worktrees()

    branch_refs = list_remote_branches()

    for ref in branch_refs:
        branch = branch_name_from_ref(ref)
        worktree_dir = WORKTREES_ROOT / branch.replace("/", "__")

        print(f"Exporting branch {ref} -> {worktree_dir}")
        add_worktree(ref, worktree_dir)

        dest_root = BRANCHES_ROOT / branch
        export_tree(worktree_dir, dest_root)
        write_branch_index(dest_root, branch)

    write_index(branch_refs)
    clean_worktrees()


if __name__ == "__main__":
    main()
