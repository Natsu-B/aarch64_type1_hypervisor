#!/usr/bin/env python3
import html
import pathlib
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable, List

# Repository root (this script is assumed to live in tools/export_branches.py)
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SITE_ROOT = REPO_ROOT / "site"
WORKTREES_ROOT = REPO_ROOT / ".worktrees"
BRANCHES_ROOT = SITE_ROOT / "branches"
COMMITS_ROOT = SITE_ROOT / "commits"

# File extensions that will be treated as text and converted to HTML
TEXT_EXTENSIONS = {
    ".rs",
    ".toml",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".xml",
    ".json",
    ".lock",
    ".cfg",
    ".conf",
    ".c",
    ".h",
    ".S",
    ".sh",
}


@dataclass
class Commit:
    full_hash: str
    short_hash: str
    author: str
    date: str
    subject: str


def run(cmd: List[str]) -> None:
    """Run a command and fail hard on error."""
    subprocess.run(cmd, check=True)


def check_output(cmd: List[str]) -> str:
    """Run a command and return stdout as text."""
    return subprocess.check_output(cmd, text=True)


def list_remote_branches() -> List[str]:
    """
    Return list of remote branch refs like 'origin/main', 'origin/gic', ...

    Exclude 'origin/HEAD'.
    """
    result = check_output(
        ["git", "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"]
    )
    branches: List[str] = []
    for line in result.splitlines():
        name = line.strip()
        if not name or name == "origin/HEAD":
            continue
        branches.append(name)
    return branches


def html_wrap(title: str, body_html: str) -> str:
    """Wrap HTML body in a minimal HTML document."""
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '<meta charset="utf-8">\n'
        f"<title>{html.escape(title)}</title>\n"
        "</head>\n"
        "<body>\n"
        f"{body_html}\n"
        "</body>\n"
        "</html>\n"
    )


def is_text_file(path: pathlib.Path) -> bool:
    """Decide whether to render this file as HTML based on its extension."""
    return path.suffix in TEXT_EXTENSIONS


DOT_PREFIX = "__dot__"

def sanitize_rel_path(rel: pathlib.Path) -> pathlib.Path:
    """
    Rewrite dot-leading path segments so they survive GitHub Pages deploy.

    Some deploy pipelines (e.g. upload-pages-artifact) exclude .git/.github,
    and Pages hosting often does not serve dot-directories. We therefore map:
      .github/foo -> __dot__github/foo
    """
    parts: List[str] = []
    for p in rel.parts:
        if p.startswith("."):
            parts.append(DOT_PREFIX + p[1:])
        else:
            parts.append(p)
    return pathlib.Path(*parts)


def unsanitize_rel_path(rel: pathlib.Path) -> pathlib.Path:
    """Reverse sanitize_rel_path for display text in indexes."""
    parts: List[str] = []
    for p in rel.parts:
        if p.startswith(DOT_PREFIX):
            parts.append("." + p[len(DOT_PREFIX):])
        else:
            parts.append(p)
    return pathlib.Path(*parts)


def export_tree(src_root: pathlib.Path, dest_root: pathlib.Path) -> None:
    """
    Export a single branch worktree to dest_root.

    Text files are converted to *.html, other files are currently skipped.
    """
    for src_path in src_root.rglob("*"):
        if src_path.is_dir():
            continue

        rel = src_path.relative_to(src_root)
        site_rel = sanitize_rel_path(rel)

        if is_text_file(src_path):
            dest_file = dest_root / site_rel
            dest_file = dest_file.parent / (dest_file.name + ".html")
            dest_file.parent.mkdir(parents=True, exist_ok=True)

            with src_path.open("r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            escaped = html.escape(content)
            body = "<pre>\n" + escaped + "\n</pre>\n"
            html_doc = html_wrap(str(rel), body)

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
    COMMITS_ROOT.mkdir(parents=True, exist_ok=True)


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

    This name is used in the URL hierarchy under /branches/ and /commits/.
    """
    if ref.startswith("origin/"):
        return ref[len("origin/") :]
    return ref


def write_root_index(branch_refs: Iterable[str]) -> None:
    """
    Write the top-level index.html listing all branches and a link to commits index.
    """
    lines = [
        "<h1>Branches</h1>",
        "<ul>",
    ]

    for ref in sorted(branch_refs):
        branch = branch_name_from_ref(ref)
        href = f"branches/{html.escape(branch)}/"
        lines.append(f'<li><a href="{href}">{html.escape(branch)}</a></li>')

    lines.append("</ul>")
    lines.append('<h2><a href="commits/index.html">Commits index</a></h2>')

    body = "\n".join(lines)
    index_html = html_wrap("Branches index", body)
    index_path = SITE_ROOT / "index.html"
    index_path.write_text(index_html, encoding="utf-8")


def write_branch_index(dest_root: pathlib.Path, branch: str) -> None:
    """
    Write index.html under dest_root listing all HTML files in the branch,
    and link to this branch's commit log page.
    """
    items: List[str] = []

    for file in sorted(dest_root.rglob("*.html")):
        rel = file.relative_to(dest_root)
        # Skip the branch index itself
        if rel == pathlib.Path("index.html"):
            continue

        href = html.escape(rel.as_posix(), quote=True)
        display_rel = unsanitize_rel_path(rel).as_posix()
        items.append(
            f'<li><a href="{href}">{html.escape(display_rel)}</a></li>'
        )

    lines = [
        f"<h1>Branch: {html.escape(branch)}</h1>",
        '<p><a href="../../commits/'
        + html.escape(branch)
        + '.html">View commit log for this branch</a></p>',
        "<ul>",
        *items,
        "</ul>",
    ]

    body = "\n".join(lines)
    index_html = html_wrap(f"{branch} branch", body)

    index_path = dest_root / "index.html"
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(index_html, encoding="utf-8")


def get_branch_commits(ref: str, max_count: int | None = None) -> List[Commit]:
    """
    Retrieve commit log for a given ref using `git log`.

    The ref is typically 'origin/main', 'origin/gic', etc.
    """
    cmd = [
        "git",
        "log",
        "--date=iso",
        "--format=%H%x1f%h%x1f%an%x1f%ad%x1f%s%x1e",
        ref,
    ]
    if max_count is not None:
        cmd.insert(2, f"-n{max_count}")

    raw = check_output(cmd)
    commits: List[Commit] = []

    # Records are separated by unit separator 0x1e, fields by 0x1f.
    for record in raw.split("\x1e"):
        record = record.strip()
        if not record:
            continue
        parts = record.split("\x1f")
        if len(parts) != 5:
            continue
        full_hash, short_hash, author, date, subject = parts
        commits.append(
            Commit(
                full_hash=full_hash,
                short_hash=short_hash,
                author=author,
                date=date,
                subject=subject,
            )
        )
    return commits


def write_commits_index(branch_refs: Iterable[str]) -> None:
    """
    Write commits/index.html listing all branches with links to their commit logs.
    """
    lines = [
        "<h1>Commits by branch</h1>",
        "<ul>",
    ]

    for ref in sorted(branch_refs):
        branch = branch_name_from_ref(ref)
        href = f"{html.escape(branch)}.html"
        lines.append(f'<li><a href="{href}">{html.escape(branch)}</a></li>')

    lines.extend(
        [
            "</ul>",
        ]
    )

    body = "\n".join(lines)
    index_html = html_wrap("Commits index", body)
    index_path = COMMITS_ROOT / "index.html"
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(index_html, encoding="utf-8")


def write_branch_commits(branch: str, commits: List[Commit]) -> None:
    """
    Write commits/<branch>.html showing commit log for the given branch.
    """
    lines: List[str] = []

    lines.append(f"<h1>Commit log for branch: {html.escape(branch)}</h1>")
    lines.append('<p><a href="index.html">Back to commits index</a></p>')
    lines.append("<table border=\"1\" cellspacing=\"0\" cellpadding=\"4\">")
    lines.append(
        "<tr>"
        "<th>Short hash</th>"
        "<th>Author</th>"
        "<th>Date (ISO)</th>"
        "<th>Subject</th>"
        "</tr>"
    )

    for c in commits:
        lines.append(
            "<tr>"
            f"<td><code>{html.escape(c.short_hash)}</code></td>"
            f"<td>{html.escape(c.author)}</td>"
            f"<td>{html.escape(c.date)}</td>"
            f"<td>{html.escape(c.subject)}</td>"
            "</tr>"
        )

    lines.append("</table>")

    body = "\n".join(lines)
    html_doc = html_wrap(f"Commits for {branch}", body)

    out_path = COMMITS_ROOT / f"{branch}.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_doc, encoding="utf-8")


def main() -> None:
    clean_site()
    clean_worktrees()

    branch_refs = list_remote_branches()

    # Export code snapshots for each branch
    for ref in branch_refs:
        branch = branch_name_from_ref(ref)
        worktree_dir = WORKTREES_ROOT / branch.replace("/", "__")

        print(f"Exporting branch {ref} -> {worktree_dir}")
        add_worktree(ref, worktree_dir)

        dest_root = BRANCHES_ROOT / branch
        export_tree(worktree_dir, dest_root)
        write_branch_index(dest_root, branch)

    # Export commit logs for each branch
    for ref in branch_refs:
        branch = branch_name_from_ref(ref)
        print(f"Exporting commits for {ref}")
        commits = get_branch_commits(ref)
        write_branch_commits(branch, commits)

    # Root indexes
    write_root_index(branch_refs)
    write_commits_index(branch_refs)

    clean_worktrees()


if __name__ == "__main__":
    main()
