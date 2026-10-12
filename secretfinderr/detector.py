import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .rules import Rule, load_rules


@dataclass
class Match:
    file_path: str
    line_number: int
    line: str
    rule_name: str
    description: str
    severity: str
    match_text: str
    start: int
    end: int


@dataclass
class ScanResult:
    matches: List[Match]
    scanned_files: int
    skipped_files: int


def _get_match_text(line: str, m: re.Match) -> str:
    text = line[m.start() : m.end()]
    if len(text) > 120:
        return text[:117] + "..."
    return text


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(4096)
        if b"\x00" in chunk:
            return True
        # heuristic: text mostly
        return False
    except Exception:
        return True


def _should_skip(path: Path, ignore_patterns: List[str] | None) -> bool:
    name = path.name.lower()
    if ignore_patterns:
        for p in ignore_patterns:
            try:
                if re.search(p, str(path), re.IGNORECASE):
                    return True
            except re.error:
                if p.lower() in str(path).lower():
                    return True
    # common build/venv
    skip_dirs = {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        "dist",
        "build",
        ".cache",
        "target",
        ".mypy_cache",
        ".ruff_cache",
        ".idea",
        ".vscode",
    }
    for part in path.parts:
        if part in skip_dirs:
            return True
    # large bin ext
    ext = path.suffix.lower()
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".woff", ".woff2", ".ttf", ".otf", ".exe", ".dll", ".so", ".dylib", ".bin", ".mp4", ".mp3", ".mov", ".avi"}:
        return True
    return False


def scan_file(
    file_path: Path,
    rules: List[Rule],
    ignore_patterns: List[str] | None = None,
    max_line_len: int = 10000,
) -> List[Match]:
    matches: List[Match] = []
    try:
        if _is_binary(file_path):
            return matches
        if _should_skip(file_path, ignore_patterns):
            return matches
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if len(line) > max_line_len:
                    # still scan truncated? keep short
                    pass
                for rule in rules:
                    try:
                        m = rule.pattern.search(line)
                    except Exception:
                        continue
                    if m:
                        matches.append(
                            Match(
                                file_path=str(file_path),
                                line_number=i,
                                line=line.rstrip("\n\r"),
                                rule_name=rule.name,
                                description=rule.description,
                                severity=rule.severity,
                                match_text=_get_match_text(line, m),
                                start=m.start(),
                                end=m.end(),
                            )
                        )
                        break  # avoid multiple rule hits same line noise? keep first
    except Exception:
        pass
    return matches


def scan_path(
    path: Path,
    rules: List[Rule],
    ignore_patterns: List[str] | None = None,
    recursive: bool = True,
) -> ScanResult:
    matches: List[Match] = []
    scanned = 0
    skipped = 0
    if path.is_file():
        scanned = 1
        matches.extend(scan_file(path, rules, ignore_patterns))
        return ScanResult(matches=matches, scanned_files=scanned, skipped_files=skipped)
    if recursive:
        for p in path.rglob("*"):
            if p.is_file():
                if _should_skip(p, ignore_patterns):
                    skipped += 1
                    continue
                scanned += 1
                matches.extend(scan_file(p, rules, ignore_patterns))
    else:
        for p in path.iterdir():
            if p.is_file():
                if _should_skip(p, ignore_patterns):
                    skipped += 1
                    continue
                scanned += 1
                matches.extend(scan_file(p, rules, ignore_patterns))
    return ScanResult(matches=matches, scanned_files=scanned, skipped_files=skipped)
