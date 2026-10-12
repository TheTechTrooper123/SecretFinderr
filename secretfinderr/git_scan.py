import subprocess
import tempfile
import os
from pathlib import Path
from typing import List, Optional

from .detector import Match, ScanResult, scan_file
from .rules import Rule


def _run(cmd: List[str], cwd: Path) -> str:
    try:
        res = subprocess.run(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return res.stdout
    except subprocess.CalledProcessError as e:
        raise RuntimeError(e.stderr or e.stdout or f"git command failed: {' '.join(cmd)}")


def scan_git(
    repo_path: Path,
    rules: List[Rule],
    max_commits: int = 100,
    branch: Optional[str] = None,
    ignore_patterns: List[str] | None = None,
) -> ScanResult:
    repo_path = repo_path.resolve()
    # ensure it's git
    _run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo_path)
    if branch:
        # try to use branch; if fails, continue with default
        try:
            _run(["git", "rev-parse", "--verify", branch], cwd=repo_path)
        except Exception:
            pass
    log_cmd = ["git", "log", "--oneline", f"-{max_commits}"]
    if branch:
        log_cmd.append(branch)
    commits = _run(log_cmd, cwd=repo_path).strip().splitlines()
    matches: List[Match] = []
    scanned_files = 0
    skipped_files = 0
    for line in commits:
        if not line.strip():
            continue
        parts = line.split()
        if not parts:
            continue
        sha = parts[0]
        # get commit info? just sha
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            # export each file? easier: git show --name-only first? then show content
            # get changed files
            try:
                name_only = _run(["git", "show", "--name-only", "--format=", sha], cwd=repo_path).strip()
            except Exception:
                continue
            for fname in name_only.splitlines():
                fname = fname.strip()
                if not fname:
                    continue
                fpath = repo_path / fname
                # skip if outside? no
                if fpath.is_dir():
                    continue
                # get content of this file at this commit
                try:
                    content = _run(["git", "show", f"{sha}:{fname}"], cwd=repo_path)
                except Exception:
                    # binary or rename; skip
                    continue
                # write temp file
                tmp = td_path / Path(fname).name
                try:
                    tmp.parent.mkdir(parents=True, exist_ok=True)
                except Exception:
                    tmp = td_path / tmp.name
                try:
                    with tmp.open("w", encoding="utf-8", errors="replace") as fh:
                        fh.write(content)
                except Exception:
                    continue
                scanned_files += 1
                for m in scan_file(tmp, rules, ignore_patterns):
                    # adjust path to show repo path + commit context
                    m.file_path = f"{repo_path}/{fname} (commit {sha})"
                    matches.append(m)
    return ScanResult(matches=matches, scanned_files=scanned_files, skipped_files=skipped_files)
