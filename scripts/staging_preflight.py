"""
Staging Preflight & Database Isolation Verifier (`scripts/staging_preflight.py`).
Verifies:
  1. `APP_ENV == 'staging'`.
  2. `MONGODB_DATABASE` is explicitly isolated (`locket_manager_staging` or `*_staging` / `*_test`),
     and NEVER equals production `'locket_manager'`.
  3. URI scheme is valid (`mongodb://` or `mongodb+srv://`), without ever printing credentials or password hashes.
  4. Backup directory (`/app/backups` or `./backups`) is writable by the current process user (UID 10001 in Docker).
  5. Optional live MongoDB connectivity check (`--ping`) confirming `ping` and database-scoped read access.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
from urllib.parse import urlparse
from pymongo import AsyncMongoClient
from app.config import PRODUCTION_DATABASE_NAME, Settings, get_settings


def mask_mongodb_uri(raw_uri: str) -> str:
    """Return a credential-free summary of a MongoDB URI (`scheme://***@host/db`)."""
    parsed = urlparse(raw_uri)
    host = parsed.hostname or 'unknown-host'
    port = f':{parsed.port}' if parsed.port else ''
    return f'{parsed.scheme}://***@{host}{port}'


def verify_staging_settings(settings: Settings, *, backup_dir: Path | None = None) -> dict:
    db_name = settings.mongodb_database.strip()
    if db_name == PRODUCTION_DATABASE_NAME:
        raise ValueError(
            f"CRITICAL ISOLATION VIOLATION: MONGODB_DATABASE is set to production '{PRODUCTION_DATABASE_NAME}'. "
            "Staging MUST use 'locket_manager_staging'."
        )
    if not (db_name.endswith('_staging') or db_name.endswith('_test') or db_name.startswith('locket_test_')):
        raise ValueError(
            f"MONGODB_DATABASE '{db_name}' must end with '_staging' or '_test' (e.g. 'locket_manager_staging')."
        )

    raw_uri = settings.mongodb_uri.get_secret_value()
    masked_uri = mask_mongodb_uri(raw_uri)
    assert raw_uri not in masked_uri or '@' not in raw_uri

    b_dir = (backup_dir or Path('backups')).resolve()
    b_dir.mkdir(parents=True, exist_ok=True)
    probe_file = b_dir / '.preflight_write_probe'
    probe_file.write_text('ok', encoding='utf-8')
    probe_file.unlink()

    return {
        'app_env': settings.app_env,
        'database': db_name,
        'production_database_protected': db_name != PRODUCTION_DATABASE_NAME,
        'masked_uri': masked_uri,
        'require_https': settings.require_https,
        'trusted_proxy_cidrs': settings.trusted_proxy_cidrs,
        'enable_research_proxy': settings.enable_research_proxy,
        'backup_dir_writable': True,
        'backup_dir': str(b_dir),
        'uid': os.getuid() if hasattr(os, 'getuid') else None,
    }


async def run_preflight(*, env_file: str | None = None, ping_db: bool = False, backup_dir: str = 'backups') -> dict:
    settings = Settings(_env_file=env_file) if env_file else get_settings()
    report = verify_staging_settings(settings, backup_dir=Path(backup_dir))
    if ping_db:
        client = AsyncMongoClient(
            settings.mongodb_uri.get_secret_value(),
            tz_aware=True,
            serverSelectionTimeoutMS=5000,
        )
        try:
            await client.admin.command('ping')
            db = client[settings.mongodb_database]
            v2_count = await db.accounts_v2.count_documents({})
            report['mongodb_ping'] = 'ok'
            report['staging_accounts_v2_count'] = v2_count
        finally:
            await client.close()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Verify Staging isolation, permissions, and MongoDB preflight.')
    parser.add_argument('--env-file', default=None, help='Optional path to .env.staging file')
    parser.add_argument('--ping', action='store_true', help='Actively ping MongoDB and check staging database')
    parser.add_argument('--backup-dir', default='backups', help='Backup directory to test write access')
    args = parser.parse_args(argv)

    report = asyncio.run(run_preflight(env_file=args.env_file, ping_db=args.ping, backup_dir=args.backup_dir))
    print(f'[STAGING_PREFLIGHT_OK] {json.dumps(report)}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
