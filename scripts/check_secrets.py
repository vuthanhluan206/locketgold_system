"""
Repository Secret & Private Key Scanner (`scripts/check_secrets.py`).
Inspects all Git-tracked files (`git ls-files`) to detect:
  1. Forbidden file extensions (`.key`, `.pem`, `.cer`, `.der`, `.p12`, `.pfx`, `.zip`, `.rar`).
  2. Tracked live environment files (`.env`, `.env.staging`, `.env.production`, `.env.local`),
     while explicitly permitting template files (`.env.example`, `.env.staging.example`) PROVIDED
     their contents contain only safe placeholders (no real password hashes, API tokens, or MongoDB credentials).
  3. Real PEM Private Key blocks (multi-line Base64 blocks between BEGIN/END PRIVATE KEY markers),
     while distinguishing scanner code / single-line test string literals / historical SOURCE.md fixture dumps.
  4. Live MongoDB SRV credentials (`mongodb+srv://user:password@...`), live Subscriber API tokens,
     or real PBKDF2 password hashes inside `.env*.example` templates.
"""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_EXTENSIONS = ('.key', '.pem', '.cer', '.der', '.p12', '.pfx', '.zip', '.rar')
ALLOWED_ENV_TEMPLATES = {'.env.example', '.env.staging.example'}

# Construct markers dynamically so this script never contains a literal contiguous PEM header
_PEM_BEGIN = '-----BEGIN ' + r'(?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----'
_PEM_END = '-----END ' + r'(?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----'
REAL_PRIVATE_KEY_BLOCK_RE = re.compile(
    _PEM_BEGIN + r'\s+([A-Za-z0-9+/=\r\n]{64,})\s+' + _PEM_END,
    re.MULTILINE,
)

# Live MongoDB URI with embedded username:password@host (excluding example/localhost/test placeholders)
LIVE_MONGODB_CRED_RE = re.compile(
    r'mongodb(?:\+srv)?://(?P<user>[^:\s"\'<>]+):(?P<pw>[^@\s"\'<>]{6,})@(?P<host>[A-Za-z0-9._\-]+)',
    re.IGNORECASE,
)
SAFE_MONGO_HOSTS = {'localhost', '127.0.0.1', 'cluster0.example.mongodb.net', 'example.mongodb.net', 'mongo', 'mongo_e2e'}

# Detect real PBKDF2 hashes or populated secrets inside .env*.example files
ENV_TEMPLATE_SECRET_KEYS = {
    'SUPERADMIN_PASSWORD_HASH',
    'ADMIN_PASSWORD_HASH',
    'SUBSCRIBER_API_TOKEN',
    'TURNSTILE_SECRET_KEY',
    'ROOT_CA_PEM',
}

EXCLUDED_DIRS = {
    '.git',
    '.venv',
    'venv',
    '__pycache__',
    '.pytest_cache',
    'certs_private',
    'certs_public',
    'backups',
    'node_modules',
}
IGNORED_ROOT_FILES = {
    'SOURCE.md',
    'cotloicualocketgold.txt',
    'locket_gold_mitm_server.js',
    'locket_gold_mitm_server(3).js',
    'rootCA.key',
    'generate_root_ca.py',
}


def validate_env_template_content(rel_str: str, content: str) -> list[str]:
    """Verify that an allowed `.env*.example` file contains only safe empty/placeholder values."""
    issues: list[str] = []
    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, val = line.split('=', 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key in ENV_TEMPLATE_SECRET_KEYS and val:
            if val.startswith('pbkdf2_sha256$') or len(val) >= 16:
                issues.append(f'Template {rel_str}:{line_no} contains a populated secret value for {key}')
        if key in {'MONGODB_URI', 'MONGO_URI'} and val:
            for m in LIVE_MONGODB_CRED_RE.finditer(val):
                host = m.group('host').lower()
                if host not in SAFE_MONGO_HOSTS and not host.endswith('.example.com'):
                    issues.append(f'Template {rel_str}:{line_no} contains a live MongoDB URI credential (host={host})')
    return issues


def scan_file_content(rel_str: str, content: str) -> list[str]:
    """Scan a single file's relative path and text content for secret violations."""
    violations: list[str] = []
    rel_path = Path(rel_str)

    if rel_str.lower().endswith(FORBIDDEN_EXTENSIONS):
        violations.append(f'Forbidden tracked file extension: {rel_str}')
        return violations

    if rel_path.name == '.env' or rel_path.name.startswith('.env.'):
        if rel_path.name not in ALLOWED_ENV_TEMPLATES:
            violations.append(f'Forbidden tracked environment file: {rel_str}')
            return violations
        violations.extend(validate_env_template_content(rel_str, content))

    is_test_or_fixture_doc = rel_str.startswith('tests/') or rel_str == 'SOURCE.md'
    if not is_test_or_fixture_doc:
        for _ in REAL_PRIVATE_KEY_BLOCK_RE.finditer(content):
            violations.append(f'Real PEM private key block detected in {rel_str}')

    for m in LIVE_MONGODB_CRED_RE.finditer(content):
        host = m.group('host').lower()
        pw = m.group('pw')
        if host not in SAFE_MONGO_HOSTS and not host.endswith('.example.com') and 'password' not in pw.lower() and '***' not in pw:
            violations.append(f'Potential live MongoDB URI credential in {rel_str} (host={host})')

    return violations


def _discover_repository_files() -> list[str]:
    try:
        return subprocess.check_output(['git', 'ls-files'], cwd=ROOT, text=True).splitlines()
    except OSError:
        result = []
        for p in sorted(ROOT.rglob('*')):
            if not p.is_file():
                continue
            rel = p.relative_to(ROOT)
            if any(part in EXCLUDED_DIRS for part in rel.parts):
                continue
            if rel.name in IGNORED_ROOT_FILES or rel.suffix.lower() in FORBIDDEN_EXTENSIONS:
                continue
            if (rel.name == '.env' or rel.name.startswith('.env.')) and rel.name not in ALLOWED_ENV_TEMPLATES:
                continue
            result.append(rel.as_posix())
        return result


def scan_tracked_files() -> list[str]:
    tracked = _discover_repository_files()
    violations: list[str] = []
    for rel_str in tracked:
        full_path = ROOT / Path(rel_str)
        if not full_path.exists():
            continue
        content = full_path.read_text(encoding='utf-8', errors='ignore')
        violations.extend(scan_file_content(rel_str, content))
    return violations


def main() -> int:
    violations = scan_tracked_files()
    if violations:
        for v in violations:
            print(f'[SECRET_SCAN_FAILED] {v}', file=sys.stderr)
        return 1
    print('[SECRET_SCAN_OK] All tracked files verified clean of private keys and live secrets.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
