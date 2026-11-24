"""
Controlled MongoDB Migration, Backup & Safe Rollback Utility for `locket_manager`.
Supports:
  --dry-run                Inspect counts, schema validity, and conflicts without writing
  --backup <file.json>     Export non-destructive JSON snapshot with SHA-256 integrity hash
  --apply                  Migrate legacy `accounts` into `accounts_v2` (requires --backup or --skip-backup)
  --rollback <file.json>   Restore `accounts_v2` from a backup snapshot file
  --mode partial|full      Rollback mode: 'partial' (default, non-destructive upsert) or 'full' (exact collection state)
  --confirm-destructive    Required when running `--rollback <file> --mode full` if newer records will be removed
"""
import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Literal
from pymongo import AsyncMongoClient
from app.config import get_settings
from app.database import run_controlled_migration
from app.models import normalize_expiry


def _json_default(obj):
    if isinstance(obj, datetime):
        return obj.astimezone(timezone.utc).isoformat()
    return str(obj)


def compute_snapshot_sha256(accounts: list[dict], accounts_v2: list[dict]) -> str:
    canonical = json.dumps(
        {'accounts': accounts, 'accounts_v2': accounts_v2},
        sort_keys=True,
        default=_json_default,
    ).encode('utf-8')
    return hashlib.sha256(canonical).hexdigest()


def verify_snapshot_integrity(snapshot: dict) -> bool:
    if not isinstance(snapshot, dict):
        raise ValueError('Invalid backup snapshot: root must be a dictionary')
    accounts = snapshot.get('accounts', [])
    accounts_v2 = snapshot.get('accounts_v2', [])
    if not isinstance(accounts, list) or not isinstance(accounts_v2, list):
        raise ValueError('Invalid backup snapshot: accounts and accounts_v2 must be lists')
    expected_hash = snapshot.get('snapshot_sha256')
    if expected_hash:
        actual_hash = compute_snapshot_sha256(accounts, accounts_v2)
        if actual_hash != expected_hash:
            raise ValueError(
                f'Snapshot SHA-256 integrity check failed! Expected {expected_hash}, got {actual_hash}'
            )
    return True


async def export_backup_to_dict(db) -> dict:
    acc_cur = db.accounts.find({}, {'_id': 0})
    acc_list = await acc_cur.to_list(length=10000) if hasattr(acc_cur, 'to_list') else []
    v2_cur = db.accounts_v2.find({}, {'_id': 0})
    v2_list = await v2_cur.to_list(length=10000) if hasattr(v2_cur, 'to_list') else []
    clean_v1 = [d.copy() for d in acc_list if isinstance(d, dict)] if isinstance(acc_list, list) else []
    clean_v2 = [d.copy() for d in v2_list if isinstance(d, dict)] if isinstance(v2_list, list) else []
    digest = compute_snapshot_sha256(clean_v1, clean_v2)
    return {
        'exported_at': datetime.now(timezone.utc).isoformat(),
        'schema_version': 2,
        'snapshot_sha256': digest,
        'accounts': clean_v1,
        'accounts_v2': clean_v2,
    }


async def preview_rollback(
    db,
    snapshot: dict,
    *,
    mode: Literal['partial', 'full'] = 'partial',
) -> dict:
    verify_snapshot_integrity(snapshot)
    records = snapshot.get('accounts_v2', [])
    snapshot_ids = {
        rec['locket_id']
        for rec in records
        if isinstance(rec, dict) and isinstance(rec.get('locket_id'), str) and rec['locket_id']
    }
    v2_cur = db.accounts_v2.find({}, {'_id': 0})
    current_v2 = await v2_cur.to_list(length=10000) if hasattr(v2_cur, 'to_list') else []
    current_ids = {
        rec['locket_id']
        for rec in (current_v2 if isinstance(current_v2, list) else [])
        if isinstance(rec, dict) and isinstance(rec.get('locket_id'), str) and rec['locket_id']
    }
    extra_ids = sorted(current_ids - snapshot_ids)
    return {
        'mode': mode,
        'snapshot_records_count': len(snapshot_ids),
        'current_records_count': len(current_ids),
        'to_upsert_count': len(snapshot_ids),
        'to_delete_count': len(extra_ids) if mode == 'full' else 0,
        'extra_ids_created_after_snapshot': extra_ids,
    }


async def restore_rollback_from_dict(
    db,
    snapshot: dict,
    *,
    mode: Literal['partial', 'full'] = 'partial',
    confirm_destructive: bool = False,
) -> dict:
    """
    Restore `accounts_v2` from a backup snapshot dictionary.
    - `mode='partial'` (default): Non-destructively upserts records present in the snapshot.
      Does NOT delete newer records created after the snapshot.
    - `mode='full'`: Restores the exact collection state at snapshot time by upserting
      snapshot records AND removing records created after the snapshot. Requires
      `confirm_destructive=True` whenever records exist that would be deleted.
    Returns a detailed summary dict (and supports integer conversion via `restored_count` key).
    """
    if mode not in {'partial', 'full'}:
        raise ValueError("Invalid rollback mode: must be 'partial' or 'full'")
    preview = await preview_rollback(db, snapshot, mode=mode)
    extra_ids = preview['extra_ids_created_after_snapshot']
    if mode == 'full' and extra_ids and not confirm_destructive:
        raise ValueError(
            f"Full rollback will delete {len(extra_ids)} record(s) created after the snapshot "
            f"({extra_ids}). Pass confirm_destructive=True (or --confirm-destructive) to proceed."
        )

    restored = 0
    records = snapshot.get('accounts_v2', [])
    for rec in records:
        if not isinstance(rec, dict) or not rec.get('locket_id'):
            continue
        doc = rec.copy()
        if isinstance(doc.get('expires_date'), str):
            try:
                doc['expires_date'] = normalize_expiry(doc['expires_date'])
            except Exception:
                pass
        await db.accounts_v2.update_one({'locket_id': doc['locket_id']}, {'$set': doc}, upsert=True)
        restored += 1

    deleted = 0
    if mode == 'full' and extra_ids:
        for lid in extra_ids:
            res = await db.accounts_v2.delete_one({'locket_id': lid})
            deleted += getattr(res, 'deleted_count', 1)

    return {
        'mode': mode,
        'restored_count': restored,
        'deleted_count': deleted,
        'deleted_ids': extra_ids if mode == 'full' else [],
    }


async def verify_post_migration(db) -> dict:
    """Verify post-migration consistency between `accounts` and `accounts_v2`."""
    acc_cur = db.accounts.find({}, {'_id': 0})
    acc_list = await acc_cur.to_list(length=10000) if hasattr(acc_cur, 'to_list') else []
    v2_cur = db.accounts_v2.find({}, {'_id': 0})
    v2_list = await v2_cur.to_list(length=10000) if hasattr(v2_cur, 'to_list') else []
    v2_ids = {
        d.get('locket_id')
        for d in (v2_list if isinstance(v2_list, list) else [])
        if isinstance(d, dict) and d.get('locket_id')
    }
    missing_in_v2 = []
    for doc in (acc_list if isinstance(acc_list, list) else []):
        if isinstance(doc, dict) and isinstance(doc.get('locket_id'), str):
            lid = doc['locket_id'].strip()
            if lid and lid not in v2_ids:
                missing_in_v2.append(lid)
    return {
        'legacy_count': len(acc_list) if isinstance(acc_list, list) else 0,
        'v2_count': len(v2_ids),
        'missing_in_v2': missing_in_v2,
        'verified': len(missing_in_v2) == 0,
    }


async def run_migration_cli(
    dry_run: bool = False,
    backup_path: str | None = None,
    rollback_path: str | None = None,
    rollback_mode: Literal['partial', 'full'] = 'partial',
    confirm_destructive: bool = False,
):
    settings = get_settings()
    client = AsyncMongoClient(
        settings.mongodb_uri.get_secret_value(),
        tz_aware=True,
        serverSelectionTimeoutMS=5000,
    )
    try:
        await client.admin.command('ping')
        db = client[settings.mongodb_database]
        legacy_count = await db.accounts.count_documents({})
        v2_count_before = await db.accounts_v2.count_documents({})
        print(f"Connected to database '{settings.mongodb_database}'.")
        print(f"Legacy accounts count: {legacy_count} | accounts_v2 count before: {v2_count_before}")

        if backup_path:
            snap = await export_backup_to_dict(db)
            Path(backup_path).write_text(json.dumps(snap, indent=2, default=_json_default), encoding='utf-8')
            print(
                f"Backup written to {backup_path} "
                f"({len(snap['accounts'])} v1, {len(snap['accounts_v2'])} v2, sha256={snap['snapshot_sha256'][:16]}...)."
            )

        if rollback_path:
            snap = json.loads(Path(rollback_path).read_text(encoding='utf-8'))
            preview = await preview_rollback(db, snap, mode=rollback_mode)
            print(f"Rollback preview: {json.dumps(preview)}")
            if dry_run:
                print("Rollback dry-run completed. No writes performed.")
                return preview
            res = await restore_rollback_from_dict(
                db,
                snap,
                mode=rollback_mode,
                confirm_destructive=confirm_destructive,
            )
            print(
                f"Rollback ({rollback_mode}) completed from {rollback_path}: "
                f"restored={res['restored_count']}, deleted={res['deleted_count']}."
            )
            return res

        report = await run_controlled_migration(db, dry_run=dry_run)
        print(
            f"Migration report (dry_run={dry_run}): "
            f"total_legacy={report['total_legacy']}, inserted={report['inserted']}, "
            f"skipped={report['skipped']}, invalid={report['invalid']}, conflict={report['conflict']}"
        )
        if not dry_run:
            verification = await verify_post_migration(db)
            print(f"Post-migration verification: {json.dumps(verification)}")
        return report
    finally:
        await client.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Migrate legacy accounts to accounts_v2 with backup & rollback.')
    parser.add_argument('--dry-run', action='store_true', help='Inspect counts and conflicts without writing')
    parser.add_argument('--apply', action='store_true', help='Apply controlled idempotent migration')
    parser.add_argument('--backup', default=None, help='Path to write JSON backup snapshot before migration')
    parser.add_argument('--rollback', default=None, help='Path to JSON backup snapshot to restore')
    parser.add_argument(
        '--mode',
        choices=['partial', 'full'],
        default='partial',
        help="Rollback mode: 'partial' (upsert only) or 'full' (restore exact snapshot state)",
    )
    parser.add_argument(
        '--confirm-destructive',
        action='store_true',
        help='Confirm deleting post-snapshot records when running --rollback with --mode full',
    )
    args = parser.parse_args()
    is_dry_run = args.dry_run or not (args.apply or args.rollback)
    asyncio.run(
        run_migration_cli(
            dry_run=is_dry_run,
            backup_path=args.backup,
            rollback_path=args.rollback,
            rollback_mode=args.mode,
            confirm_destructive=args.confirm_destructive,
        )
    )
