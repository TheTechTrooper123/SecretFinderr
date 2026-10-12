import re
from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    description: str
    severity: str = "high"  # high/medium/low
    examples: List[str] | None = None


DEFAULT_RULES: List[Rule] = [
    Rule(
        name="AWS Access Key",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        description="AWS access key ID",
        severity="high",
        examples=["AKIAIOSFODNN7EXAMPLE"],
    ),
    Rule(
        name="AWS Secret Key",
        pattern=re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]?"),
        description="AWS secret access key",
        severity="high",
    ),
    Rule(
        name="GitHub Personal Access Token",
        pattern=re.compile(r"ghp_[A-Za-z0-9]{20,}"),
        description="GitHub personal access token",
        severity="high",
        examples=["ghp_1234567890abcdefghijklmnopqrstuvwx"],
    ),
    Rule(
        name="GitHub Fine-grained PAT",
        pattern=re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
        description="GitHub fine-grained personal access token",
        severity="high",
    ),
    Rule(
        name="Google API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        description="Google API key",
        severity="high",
    ),
    Rule(
        name="OpenAI API Key",
        pattern=re.compile(r"sk-(?:live|proj|svcacct)?-[A-Za-z0-9]{20,48}"),
        description="OpenAI API key",
        severity="high",
    ),
    Rule(
        name="Slack Token",
        pattern=re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}"),
        description="Slack token",
        severity="high",
    ),
    Rule(
        name="Stripe Secret Key",
        pattern=re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,99}"),
        description="Stripe secret key",
        severity="high",
    ),
    Rule(
        name="Private Key PEM",
        pattern=re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP|PRIVATE KEY)-----"),
        description="Private key block",
        severity="critical",
    ),
    Rule(
        name="Generic API Key",
        pattern=re.compile(r"(?i)(?:api[_-]?key|apikey|secret|password)['\"]?\s*[:=]\s*['\"][a-z0-9_\-]{16,}['\"]"),
        description="Generic key/secret assignment",
        severity="medium",
    ),
    Rule(
        name="JWT Token",
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        description="JSON Web Token",
        severity="medium",
    ),
]


def load_rules(custom_rules: List[Dict[str, Any]] | None = None) -> List[Rule]:
    rules = list(DEFAULT_RULES)
    if not custom_rules:
        return rules
    for cr in custom_rules:
        try:
            rules.append(
                Rule(
                    name=cr["name"],
                    pattern=re.compile(cr["pattern"]),
                    description=cr.get("description", ""),
                    severity=cr.get("severity", "medium"),
                    examples=cr.get("examples", []),
                )
            )
        except Exception:
            continue
    return rules
