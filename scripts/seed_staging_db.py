"""
Isolated Staging Database Seeder (`scripts/seed_staging_db.py`).
Populates synthetic test accounts into `locket_manager_staging` for Staging verification.
HARD SAFETY GUARD:
  Refuses to execute if `MONGODB_DATABASE == 'locket_manager'` (production) or if the database name
  does not end with `_staging` or `_test`. Never touches production collections.
"""
import argparse
import asyncio
from datetime import datetime, timedelta, timezone
import json
from pymongo import AsyncMongoClient
from app.config import PRODUCTION_DATABASE_NAME, Settings, get_settings


def assert_safe_staging_db_name(db_name: str) -> None:
    clean = (db_name or '').strip()
    if clean == PRODUCTION_DATABASE_NAME or not (
        clean.endswith('_staging') or clean.endswith('_test') or clean.startswith('locket_test_')
    ):
        raise RuntimeError(
            f"SAFETY ABORT: Refusing to seed database '{clean}'. "
            f"Seeding is only permitted on isolated staging/test databases (e.g. 'locket_manager_staging'), "
            f"NEVER on production '{PRODUCTION_DATABASE_NAME}'."
        )


async def seed_staging_accounts(db, *, db_name: str) -> dict:
    assert_safe_staging_db_name(db_name)
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=90)
    past = now - timedelta(days=15)

    synthetic_accounts = [
        {
            'schema_version': 2,
            'locket_id': 'staging_active_user',
            'account_id': 'staging_active_user',
            'username': 'staging_active_user',
            'firebase_uid': None,
            'verification_status': 'unverified_handle',
            'verification_method': 'link_handle_only',
            'verification_source': 'staging_synthetic_seed',
            '_server_uid_proof': False,
            'status': 'active',
            'product_identifier': 'com.locket.gold.yearly',
            'expires_date': future,
            'revoked_at': None,
            'revoke_reason': None,
            'max_devices': 2,
            'notes': 'Synthetic active staging test account',
            'updated_at': now,
        },
        {
            'schema_version': 2,
            'locket_id': 'staging_expired_user',
            'account_id': 'staging_expired_user',
            'username': 'staging_expired_user',
            'firebase_uid': None,
            'verification_status': 'unverified_handle',
            'verification_method': 'link_handle_only',
            'verification_source': 'staging_synthetic_seed',
            '_server_uid_proof': False,
            'status': 'expired',
            'product_identifier': 'com.locket.gold.yearly',
            'expires_date': past,
            'revoked_at': None,
            'revoke_reason': None,
            'max_devices': 2,
            'notes': 'Synthetic expired staging test account',
            'updated_at': now,
        },
        {
            'schema_version': 2,
            'locket_id': 'staging_revoked_user',
            'account_id': 'staging_revoked_user',
            'username': 'staging_revoked_user',
            'firebase_uid': None,
            'verification_status': 'unverified_handle',
            'verification_method': 'link_handle_only',
            'verification_source': 'staging_synthetic_seed',
            '_server_uid_proof': False,
            'status': 'revoked',
            'product_identifier': 'com.locket.gold.yearly',
            'expires_date': future,
            'revoked_at': now,
            'revoke_reason': 'Synthetic revoked staging test account',
            'max_devices': 2,
            'notes': 'Synthetic revoked staging test account',
            'updated_at': now,
        },
    ]

    seeded_ids = []
    for doc in synthetic_accounts:
        lid = doc['locket_id']
        await db.accounts_v2.update_one({'locket_id': lid}, {'$set': doc}, upsert=True)
        await db.accounts.update_one(
            {'locket_id': lid},
            {
                '$set': {
                    'locket_id': lid,
                    'expires_date': doc['expires_date'],
                    'status': doc['status'],
                    'revoked_at': doc['revoked_at'],
                }
            },
            upsert=True,
        )
        seeded_ids.append(lid)

    return {
        'database': db_name,
        'seeded_count': len(seeded_ids),
        'seeded_ids': seeded_ids,
    }


async def run_seeder(*, env_file: str | None = None) -> dict:
    settings = Settings(_env_file=env_file) if env_file else get_settings()
    assert_safe_staging_db_name(settings.mongodb_database)
    client = AsyncMongoClient(
        settings.mongodb_uri.get_secret_value(),
        tz_aware=True,
        serverSelectionTimeoutMS=5000,
    )
    try:
        await client.admin.command('ping')
        db = client[settings.mongodb_database]
        return await seed_staging_accounts(db, db_name=settings.mongodb_database)
    finally:
        await client.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Seed synthetic accounts into isolated staging database.')
    parser.add_argument('--env-file', default=None, help='Optional path to .env.staging file')
    args = parser.parse_args(argv)
    res = asyncio.run(run_seeder(env_file=args.env_file))
    print(f'[STAGING_SEED_OK] {json.dumps(res)}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
