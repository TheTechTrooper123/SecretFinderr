import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

from . import __version__
from .detector import scan_path, Match, ScanResult
from .rules import load_rules
from .git_scan import scan_git


def _match_to_dict(m: Match) -> Dict[str, Any]:
    return {
        "file_path": m.file_path,
        "line_number": m.line_number,
        "rule_name": m.rule_name,
        "description": m.description,
        "severity": m.severity,
        "match_text": m.match_text,
        "line": m.line,
    }


def _load_custom_rules(path: Path) -> List[Dict[str, Any]]:
    try:
        if path.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore
            except Exception:
                print("PyYAML not installed; cannot load YAML rules", file=sys.stderr)
                return []
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or []
        else:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f) or []
        if isinstance(data, dict):
            data = data.get("rules", [])
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
    except Exception as e:
        print(f"Failed to load rules from {path}: {e}", file=sys.stderr)
    return []


def _print_human(res: ScanResult) -> None:
    items = res.matches
    if not items:
        print("No secrets found.")
        return
    print(f"Found {len(items)} potential secret(s):\n")
    for m in items:
        rel = m.file_path
        try:
            p = Path(m.file_path)
            if p.is_absolute():
                cwd = Path.cwd()
                try:
                    rel = str(p.relative_to(cwd))
                except Exception:
                    rel = m.file_path
        except Exception:
            rel = m.file_path
        print(f"• [{m.severity.upper()}] {m.rule_name} — {m.description}")
        print(f"  {rel}:{m.line_number}")
        print(f"  > {m.match_text}")
        print()


def _print_json(result: ScanResult) -> None:
    data = {
        "version": __version__,
        "scanned_files": result.scanned_files,
        "skipped_files": result.skipped_files,
        "matches": [_match_to_dict(m) for m in result.matches],
    }
    print(json.dumps(data, indent=2))


def _print_sarif(result: ScanResult) -> None:
    rules_list = []
    results = []
    for m in result.matches:
        results.append(
            {
                "ruleId": m.rule_name,
                "level": "error" if m.severity in ("high", "critical") else "warning",
                "message": {"text": f"{m.description}: {m.match_text}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": m.file_path},
                            "region": {"startLine": m.line_number},
                        }
                    }
                ],
            }
        )
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secretfinderr",
                        "version": __version__,
                        "rules": rules_list,
                    }
                },
                "results": results,
            }
        ],
    }
    print(json.dumps(sarif, indent=2))


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="secretfinderr", description="Local AI-free secrets scanner")
    p.add_argument("--version", action="version", version=f"secretfinderr {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="Scan files, directories or git history")
    sp.add_argument("path", nargs="?", default=".", help="Path to scan (default: .)")
    sp.add_argument("--git", action="store_true", help="Scan git history instead of working tree")
    sp.add_argument("--max-commits", type=int, default=100, help="Max commits when --git (default: 100)")
    sp.add_argument("--branch", help="Branch to scan when --git (default: current)")
    sp.add_argument("--format", choices=["human", "json", "sarif"], default="human", help="Output format")
    sp.add_argument("--rules", help="Path to custom rules JSON/YAML")
    sp.add_argument("--ignore", action="append", help="Ignore pattern (regex, can be repeated)")
    sp.add_argument("--no-recursive", action="store_true", help="Do not scan recursively")

    args = p.parse_args(argv)

    custom = []
    if args.rules:
        custom = _load_custom_rules(Path(args.rules))
    rules = load_rules(custom)

    if args.git:
        try:
            res = scan_git(
                repo_path=Path(args.path),
                rules=rules,
                max_commits=args.max_commits,
                branch=args.branch,
                ignore_patterns=args.ignore,
            )
        except Exception as e:
            print(f"Git scan failed: {e}", file=sys.stderr)
            return 2
    else:
        res = scan_path(
            path=Path(args.path),
            rules=rules,
            ignore_patterns=args.ignore,
            recursive=not args.no_recursive,
        )

    if args.format == "json":
        _print_json(res)
    elif args.format == "sarif":
        _print_sarif(res)
    else:
        _print_human(res)

    if res.matches:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
