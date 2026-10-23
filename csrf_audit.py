
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
SKIP_DIRS = {
    ".git", ".venv", ".venv-1", "venv", "env",
    "__pycache__", "node_modules", ".idea",
    ".vscode", "dist", "build"
}
EXTENSIONS = {".py", ".html", ".js"}
PATTERNS = {
    "Python write route": r"methods\s*=\s*[\[\(][^\]\)]*['\"](?:POST|PUT|PATCH|DELETE)['\"]",
    "HTML form": r"<form\b",
    "HTML CSRF token": r"csrf_token",
    "JS write request": r"\b(?:fetch|axios|XMLHttpRequest)\b|method\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]",
    "CSRF configuration": r"WTF_CSRF_|CSRFProtect|csrf\.protect|csrf\.exempt",
}

print("\nATTACKLENS - CSRF FILE AUDIT")
print("=" * 65)

results = []

for path in sorted(ROOT.rglob("*")):
    if not path.is_file():
        continue
    if any(part.lower() in SKIP_DIRS for part in path.relative_to(ROOT).parts):
        continue
    if path.name.lower().startswith(".env"):
        continue
    if path.name == "csrf_audit.py" or path.suffix.lower() not in EXTENSIONS:
        continue

    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        continue

    matches = [
        name for name, pattern in PATTERNS.items()
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL)
    ]

    if matches:
        results.append((path.relative_to(ROOT), matches))
        print(f"\n{path.relative_to(ROOT)}")
        for match in matches:
            print(f"  - {match}")

print("\n" + "=" * 65)
print(f"Potentially relevant files: {len(results)}")
print("Read-only audit complete. No files modified.")
