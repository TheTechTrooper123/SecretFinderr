# SecretFinderr

AI-free CLI tool to detect API keys, passwords, tokens, and other secrets in code repositories and Git history. It shows findings, supports custom detection rules, and runs entirely locally.

## Features

- **Local & AI-free**: No telemetry, no external API calls, runs offline.
- **Scan files & directories**: Recursively scans code for common secret patterns.
- **Git history aware**: Scan commits, branches, or full history for leaked secrets.
- **Custom rules**: Define your own regex-based detection rules via JSON/YAML.
- **Clear output**: Human-readable table, JSON, or SARIF for CI integration.
- **Safe defaults**: Skips common binary/build directories and large binaries.
- **Zero external dependencies**: Only Python 3.9+ standard library.

## Installation

```bash
pipx install secretfinderr  # recommended
# or
pip install secretfinderr
# or from source
git clone https://github.com/TheTechTrooper123/SecretFinderr.git
cd SecretFinderr
pip install -e .
```

## Usage

```bash
# Scan current directory
secretfinderr scan .

# Scan a specific file
secretfinderr scan path/to/file.py

# Scan Git history (last 50 commits)
secretfinderr scan --git --max-commits 50 .

# Output as JSON
secretfinderr scan . --format json

# Use custom rules
secretfinderr scan . --rules custom-rules.json

# Ignore patterns
secretfinderr scan . --ignore ".*\\.lock$" --ignore "tests/fixtures/.*"
```

## Custom Rules

Create a JSON file:

```json
[
  {
    "name": "Internal API Token",
    "pattern": "int_api_[A-Za-z0-9]{32}",
    "description": "Internal service API token",
    "severity": "high"
  }
]
```

## Exit Codes

- `0` – No secrets found
- `1` – Secrets found
- `2` – Error occurred

## License

MIT
