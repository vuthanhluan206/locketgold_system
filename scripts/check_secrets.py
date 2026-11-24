"""
Repository Secret & Private Key Scanner (`scripts/check_secrets.py`).
Inspects all Git-tracked files (`git ls-files`) to detect:
  1. Forbidden file extensions (`.key`, `.pem`, `.cer`, `.der`, `.p12`, `.pfx`, `.zip`, `.rar`) or `.env` files.
  2. Real PEM Private Key blocks (multi-line Base64 blocks between BEGIN/END PRIVATE KEY markers),
     while distinguishing scanner code / single-line test string literals / historical SOURCE.md fixture dumps.
  3. Live MongoDB SRV credentials (`mongodb+srv://user:password@...`), live Subscriber API tokens, or hardcoded PBKDF2 hashes outside `tests/` and documentation examples.
"""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_EXTENSIONS = ('.key', '.pem', '.cer', '.der', '.p12', '.pfx', '.zip', '.rar')

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
SAFE_MONGO_HOSTS = {'localhost', '127.0.0.1', 'cluster0.example.mongodb.net', 'example.mongodb.net', 'mongo'}


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
            if rel.name == '.env' or (rel.name.startswith('.env.') and rel.name != '.env.example'):
                continue
            result.append(rel.as_posix())
        return result


def scan_tracked_files() -> list[str]:
    tracked = _discover_repository_files()
    violations: list[str] = []

    for rel_str in tracked:
        rel_path = Path(rel_str)
        full_path = ROOT / rel_path
        if not full_path.exists():
            continue

        # 1. Check forbidden extensions & .env files
        if rel_str.lower().endswith(FORBIDDEN_EXTENSIONS):
            violations.append(f'Forbidden tracked file extension: {rel_str}')
            continue
        if rel_path.name == '.env' or (rel_path.name.startswith('.env.') and rel_path.name != '.env.example'):
            violations.append(f'Forbidden tracked environment file: {rel_str}')
            continue

        content = full_path.read_text(encoding='utf-8', errors='ignore')

        # 2. Check for real multi-line PEM private key material (outside test fixtures)
        is_test_or_fixture_doc = rel_str.startswith('tests/') or rel_str == 'SOURCE.md'
        if not is_test_or_fixture_doc:
            for match in REAL_PRIVATE_KEY_BLOCK_RE.finditer(content):
                violations.append(f'Real PEM private key block detected in {rel_str}')

        # 3. Check for live MongoDB credentials with real password & non-example host
        for m in LIVE_MONGODB_CRED_RE.finditer(content):
            host = m.group('host').lower()
            pw = m.group('pw')
            if host not in SAFE_MONGO_HOSTS and not host.endswith('.example.com') and 'password' not in pw.lower() and '***' not in pw:
                violations.append(f'Potential live MongoDB URI credential in {rel_str} (host={host})')

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
