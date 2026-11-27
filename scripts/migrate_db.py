"""
Controlled MongoDB Migration, Backup & Safe Rollback Utility for `locket_manager`.
Supports:
  --dry-run                Inspect counts, schema validity, and conflicts without writing
  --backup <file.json>     Export non-destructive JSON snapshot with SHA-256 integrity hash (no 10k truncation)
  --verify-backup <file>   Verify backup file existence, non-empty size, record counts, and SHA-256 hash on host disk
  --apply                  Migrate legacy `accounts` into `accounts_v2`
  --rollback <file.json>   Restore `accounts_v2` from a backup snapshot file
  --mode partial|full      Rollback mode: 'partial' (default, non-destructive upsert) or 'full' (exact collection state)
  --confirm-destructive    Required when running `--rollback <file> --mode full` if newer records will be removed
"""
import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Literal
from bson import json_util
from pymongo import AsyncMongoClient
from app.config import get_settings
from app.database import _fetch_all_documents, run_controlled_migration
from app.models import compute_entitlement_status, normalize_expiry
from app.services.entitlement_service import extract_verified_uid_metadata
from app.services.identity_service import is_valid_firebase_uid


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
    if 'uid_migration_version' in snapshot:
        raise ValueError('Use --uid-entitlements --rollback with a UID migration journal')
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
    expected_v1_count = snapshot.get('accounts_count')
    expected_v2_count = snapshot.get('accounts_v2_count')
    if expected_v1_count is not None and len(accounts) != expected_v1_count:
        raise ValueError(
            f'Snapshot accounts count mismatch! Expected {expected_v1_count}, got {len(accounts)}'
        )
    if expected_v2_count is not None and len(accounts_v2) != expected_v2_count:
        raise ValueError(
            f'Snapshot accounts_v2 count mismatch! Expected {expected_v2_count}, got {len(accounts_v2)}'
        )
    return True


def verify_backup_file_on_disk(backup_path: str | Path) -> dict:
    """
    Verify that a backup snapshot file exists on persistent disk (not lost inside an ephemeral --rm container),
    is non-empty, valid JSON, and passes SHA-256 + record count integrity checks.
    """
    path = Path(backup_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f'Backup file does not exist on disk: {path}')
    size_bytes = path.stat().st_size
    if size_bytes == 0:
        raise ValueError(f'Backup file is empty (0 bytes): {path}')
    snapshot = json.loads(path.read_text(encoding='utf-8'))
    verify_snapshot_integrity(snapshot)
    return {
        'path': str(path),
        'size_bytes': size_bytes,
        'exported_at': snapshot.get('exported_at'),
        'snapshot_sha256': snapshot.get('snapshot_sha256'),
        'accounts_count': len(snapshot.get('accounts', [])),
        'accounts_v2_count': len(snapshot.get('accounts_v2', [])),
        'verified': True,
    }


async def export_backup_to_dict(db) -> dict:
    """Export all documents from `accounts` and `accounts_v2` without any 10,000-record truncation cap."""
    acc_list = await _fetch_all_documents(getattr(db, 'accounts', None), {}, {'_id': 0})
    v2_list = await _fetch_all_documents(getattr(db, 'accounts_v2', None), {}, {'_id': 0})
    clean_v1 = [d.copy() for d in acc_list if isinstance(d, dict)]
    clean_v2 = [d.copy() for d in v2_list if isinstance(d, dict)]
    digest = compute_snapshot_sha256(clean_v1, clean_v2)
    return {
        'exported_at': datetime.now(timezone.utc).isoformat(),
        'schema_version': 2,
        'scope': 'collection_snapshot_accounts_and_accounts_v2',
        'accounts_count': len(clean_v1),
        'accounts_v2_count': len(clean_v2),
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
    current_v2 = await _fetch_all_documents(getattr(db, 'accounts_v2', None), {}, {'_id': 0})
    current_ids = {
        rec['locket_id']
        for rec in current_v2
        if isinstance(rec, dict) and isinstance(rec.get('locket_id'), str) and rec['locket_id']
    }
    extra_ids = sorted(current_ids - snapshot_ids)
    return {
        'mode': mode,
        'rollback_scope': 'collection_accounts_v2',
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
    Restore `accounts_v2` collection from a backup snapshot dictionary.
    Note: This performs a collection-level rollback on `accounts_v2` (leaving `admins`, `sessions`,
    `audit`, and legacy `accounts` untouched), as opposed to a full database-wide mongorestore.
    - `mode='partial'` (default): Non-destructively upserts records present in the snapshot.
      Does NOT delete newer records created after the snapshot.
    - `mode='full'`: Restores the exact `accounts_v2` collection state at snapshot time by upserting
      snapshot records AND removing records created after the snapshot. Requires
      `confirm_destructive=True` whenever records exist that would be deleted.
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
        'rollback_scope': 'collection_accounts_v2',
        'restored_count': restored,
        'deleted_count': deleted,
        'deleted_ids': extra_ids if mode == 'full' else [],
    }


async def verify_post_migration(db) -> dict:
    """Verify post-migration consistency between `accounts` and `accounts_v2` without truncation."""
    acc_list = await _fetch_all_documents(getattr(db, 'accounts', None), {}, {'_id': 0})
    v2_list = await _fetch_all_documents(getattr(db, 'accounts_v2', None), {}, {'_id': 0})
    v2_ids = {
        d.get('locket_id')
        for d in v2_list
        if isinstance(d, dict) and d.get('locket_id')
    }
    missing_in_v2 = []
    for doc in acc_list:
        if isinstance(doc, dict) and isinstance(doc.get('locket_id'), str):
            lid = doc['locket_id'].strip()
            if lid and lid not in v2_ids:
                missing_in_v2.append(lid)
    return {
        'legacy_count': len(acc_list),
        'v2_count': len(v2_ids),
        'missing_in_v2': missing_in_v2,
        'verified': len(missing_in_v2) == 0,
    }


async def reconcile_collections(db, *, dry_run: bool = True) -> dict:
    """
    Detect and safely reconcile partial write drift across `accounts_v2` (canonical),
    `accounts` (legacy mirror), and `entitlements` (Gold projection).
    Safety Invariants:
    1. Canonical `accounts_v2` is authoritative.
    2. NEVER resurrects or re-activates a record that is marked `revoked` in EITHER `accounts_v2` or `accounts`
       (if `accounts` is revoked while `accounts_v2` was active due to an interrupted revoke call,
       reconciliation propagates `revoked` into `accounts_v2` and `entitlements` — fail-closed!).
    3. Ensures `accounts` and `entitlements` match the authoritative status and `expires_date` of `accounts_v2`.
    """
    now = datetime.now(timezone.utc)
    v1_list = await _fetch_all_documents(getattr(db, 'accounts', None), {}, {'_id': 0})
    v2_list = await _fetch_all_documents(getattr(db, 'accounts_v2', None), {}, {'_id': 0})
    ent_list = await _fetch_all_documents(getattr(db, 'entitlements', None), {'entitlement_key': 'Gold'}, {'_id': 0})

    v1_map = {d['locket_id']: d for d in v1_list if isinstance(d, dict) and isinstance(d.get('locket_id'), str)}
    v2_map = {d['locket_id']: d for d in v2_list if isinstance(d, dict) and isinstance(d.get('locket_id'), str)}
    ent_map = {d['account_id']: d for d in ent_list if isinstance(d, dict) and isinstance(d.get('account_id'), str)}

    drifts = []
    repaired = 0

    for lid, v2_doc in v2_map.items():
        v1_doc = v1_map.get(lid)
        ent_doc = ent_map.get(lid)

        v2_status = str(v2_doc.get('status') or 'active').lower()
        v1_status = str(v1_doc.get('status') or '').lower() if isinstance(v1_doc, dict) else ''
        v2_revoked = v2_status == 'revoked' or v2_doc.get('revoked_at') is not None
        v1_revoked = isinstance(v1_doc, dict) and (v1_status == 'revoked' or v1_doc.get('revoked_at') is not None)

        # Fail-closed revocation: if either v1 or v2 is revoked, canonical status MUST be revoked
        auth_status = 'revoked' if (v2_revoked or v1_revoked) else v2_status
        auth_revoked_at = (
            (v2_doc.get('revoked_at') or (v1_doc.get('revoked_at') if isinstance(v1_doc, dict) else None) or now)
            if auth_status == 'revoked'
            else None
        )
        try:
            auth_expiry = normalize_expiry(v2_doc.get('expires_date'))
        except Exception:
            auth_expiry = datetime(1970, 1, 1, tzinfo=timezone.utc)

        # Check if v2 itself needs fail-closed revocation propagation from v1
        if auth_status == 'revoked' and v2_status != 'revoked':
            drifts.append({'locket_id': lid, 'target': 'accounts_v2', 'reason': 'Propagate revoked state from legacy accounts'})
            if not dry_run:
                await db.accounts_v2.update_one(
                    {'locket_id': lid},
                    {'$set': {'status': 'revoked', 'revoked_at': auth_revoked_at, 'updated_at': now}},
                )
                repaired += 1

        # Check legacy accounts mirror drift
        v1_exp = None
        if isinstance(v1_doc, dict) and v1_doc.get('expires_date') is not None:
            try:
                v1_exp = normalize_expiry(v1_doc['expires_date'])
            except Exception:
                v1_exp = None

        if v1_doc is None or v1_exp != auth_expiry or (auth_status == 'revoked' and v1_status != 'revoked'):
            drifts.append({'locket_id': lid, 'target': 'accounts', 'reason': 'Legacy mirror out of sync with accounts_v2'})
            if not dry_run and getattr(db, 'accounts', None) is not None:
                await db.accounts.update_one(
                    {'locket_id': lid},
                    {
                        '$set': {
                            'locket_id': lid,
                            'expires_date': auth_expiry,
                            'status': auth_status,
                            'revoked_at': auth_revoked_at,
                        }
                    },
                    upsert=True,
                )
                repaired += 1

        # Check entitlements projection drift
        if getattr(db, 'entitlements', None) is not None:
            fb_uid, uid_ver, *_ = extract_verified_uid_metadata(v2_doc)
            target_ent_id = fb_uid if (uid_ver and fb_uid) else lid
            ent_doc = ent_map.get(target_ent_id) or ent_map.get(lid)
            ent_exp = None
            if isinstance(ent_doc, dict) and ent_doc.get('expires_date') is not None:
                try:
                    ent_exp = normalize_expiry(ent_doc['expires_date'])
                except Exception:
                    ent_exp = None
            ent_status = str(ent_doc.get('status') or '').lower() if isinstance(ent_doc, dict) else ''
            if auth_status == 'active':
                if not uid_ver or not ent_doc or ent_doc.get('account_id') != fb_uid:
                    auth_status = 'pending'
                elif ent_status != 'active' or ent_doc.get('revoked_at'):
                    auth_status = 'revoked' if ent_doc.get('revoked_at') or ent_status == 'revoked' else 'pending'
                if uid_ver and ent_exp is not None:
                    auth_expiry = min(auth_expiry, ent_exp)
            if ent_doc is None or ent_doc.get('account_id') != target_ent_id or ent_exp != auth_expiry or ent_status != auth_status:
                drifts.append({'locket_id': lid, 'target': 'entitlements', 'reason': 'Entitlement projection out of sync with accounts_v2'})
                if not dry_run:
                    await db.entitlements.update_one(
                        {'account_id': target_ent_id, 'entitlement_key': 'Gold'},
                        {
                            '$set': {
                                'account_id': target_ent_id,
                                'entitlement_key': 'Gold',
                                'product_identifier': 'com.locket.gold.yearly',
                                'status': auth_status,
                                'expires_date': auth_expiry,
                                'revoked_at': auth_revoked_at,
                                'updated_at': now,
                            }
                        },
                        upsert=True,
                    )
                    repaired += 1

    return {
        'dry_run': dry_run,
        'checked_v2_records': len(v2_map),
        'drift_count': len(drifts),
        'repaired_operations': repaired,
        'drifts': drifts,
    }


async def inspect_and_migrate_uid_entitlements(db, *, dry_run: bool = True, changes_out=None) -> dict:
    """
    Controlled UID-Key Entitlement Audit & Migration (Prompt 26 Section 10):
      1. Lists accounts currently using username as key (`username_keyed_accounts`).
      2. Lists accounts with a verified Firebase UID (`verified_uid_accounts`).
      3. Detects duplicate UIDs across different accounts (`duplicate_uids`) and orphan entitlements (`orphan_entitlements`).
      4. Generates an old-key -> new-verified-UID mapping report (`old_to_new_mapping`).
      5. Never auto-converts username-only accounts into `verified_uid` and never overwrites verified UIDs.
      6. Halts immediately (`aborted_on_conflict=True`) without writing if any UID conflict is detected.
    """
    now = datetime.now(timezone.utc)
    v2_list = await _fetch_all_documents(getattr(db, 'accounts_v2', None), {}, {'_id': 0})
    ent_list = await _fetch_all_documents(getattr(db, 'entitlements', None), {'entitlement_key': 'Gold'}, {'_id': 0})

    username_keyed_accounts: list[dict] = []
    verified_uid_accounts: list[dict] = []
    old_to_new_mapping: list[dict] = []
    duplicate_uids: list[dict] = []
    orphan_entitlements: list[dict] = []
    unverified_active_entitlements: list[dict] = []

    uid_owners: dict[str, list[str]] = {}
    known_locket_ids: set[str] = set()
    known_verified_uids: set[str] = set()
    v2_by_lid: dict[str, dict] = {}
    active_keys = {e.get('account_id') for e in ent_list if e.get('status') == 'active'}

    for doc in v2_list:
        if not isinstance(doc, dict):
            continue
        lid = str(doc.get('locket_id') or '').strip()
        if not lid:
            continue
        known_locket_ids.add(lid)
        v2_by_lid[lid] = doc

        raw_uid = doc.get('firebase_uid')
        if isinstance(raw_uid, str) and raw_uid.strip():
            uid_owners.setdefault(raw_uid.strip(), []).append(lid)

        fb_uid, uid_verified, ver_status, _, ver_source = extract_verified_uid_metadata(doc)
        if uid_verified and fb_uid and is_valid_firebase_uid(fb_uid):
            known_verified_uids.add(fb_uid)
            verified_uid_accounts.append({
                'locket_id': lid,
                'username': doc.get('username') or lid,
                'firebase_uid': fb_uid,
                'account_id': doc.get('account_id'),
                'verification_source': ver_source,
                'status': doc.get('status'),
            })
            if doc.get('account_id') != fb_uid or (lid != fb_uid and lid in active_keys):
                old_to_new_mapping.append({
                    'locket_id': lid,
                    'old_key': str(doc.get('account_id') or lid),
                    'new_verified_uid': fb_uid,
                    'status': doc.get('status', 'active'),
                })
        else:
            username_keyed_accounts.append({
                'locket_id': lid,
                'username': doc.get('username') or lid,
                'firebase_uid': fb_uid,
                'verification_status': ver_status,
                'status': doc.get('status', 'pending'),
            })

    for uid_val, owners in sorted(uid_owners.items()):
        if len(owners) > 1:
            duplicate_uids.append({'firebase_uid': uid_val, 'locket_ids': owners})

    changes = []
    def change(collection, key, before, fields):
        changes.append({'collection': collection, 'key': key, 'before': before,
                        'after': {**(before or {}), **key, **fields}})

    grants = {}
    for ent in ent_list:
        if ent.get('entitlement_key') != 'Gold':
            continue
        aid = ent['account_id']
        if aid in grants:
            duplicate_uids.append({'account_id': aid, 'reason': 'Duplicate Gold grants'})
        grants[aid] = ent
        owners = uid_owners.get(aid, [])
        if owners and ent.get('locket_id') and ent['locket_id'] not in owners:
            duplicate_uids.append({'account_id': aid, 'reason': 'Grant belongs to another account'})
        if aid in known_verified_uids:
            if aid in known_locket_ids and owners != [aid]:
                duplicate_uids.append({'account_id': aid, 'reason': 'UID collides with another account key'})
            continue
        if aid not in known_locket_ids:
            orphan_entitlements.append({'account_id': aid, 'status': ent.get('status')})
        elif ent.get('locket_id', aid) != aid:
            duplicate_uids.append({'account_id': aid, 'reason': 'Legacy grant belongs to another account'})
        if ent.get('status') == 'active':
            unverified_active_entitlements.append({'account_id': aid, 'status': 'active'})
            change('entitlements', {'account_id': aid, 'entitlement_key': 'Gold'}, ent,
                   {'status': 'revoked', 'revoked_at': now, 'updated_at': now})

    migrated_entitlements = downgraded_pending = 0
    for mapping in old_to_new_mapping:
        lid, uid = mapping['locket_id'], mapping['new_verified_uid']
        account = v2_by_lid[lid]
        if account.get('account_id') != uid:
            change('accounts_v2', {'locket_id': lid}, account, {'account_id': uid, 'updated_at': now})
        old = grants.get(lid)
        # Never mint a grant from account status or resurrect an existing revoked UID grant.
        if uid not in grants and old and old.get('locket_id', lid) == lid:
            status, expiry = compute_entitlement_status(old, now)
            if account.get('status') != 'active' or old.get('status') != 'active':
                status = 'revoked' if 'revoked' in (account.get('status'), old.get('status')) else 'pending'
            fields = {**old, 'account_id': uid, 'locket_id': lid, 'status': status,
                      'expires_date': expiry, 'updated_at': now}
            change('entitlements', {'account_id': uid, 'entitlement_key': 'Gold'}, None, fields)
            migrated_entitlements += 1

    for item in username_keyed_accounts:
        if item['status'] == 'active':
            lid = item['locket_id']
            account = v2_by_lid[lid]
            change('accounts_v2', {'locket_id': lid}, account, {
                'status': 'pending', 'verification_status': item['verification_status'],
                '_server_uid_proof': False, 'updated_at': now,
            })
            downgraded_pending += 1

    has_conflicts = bool(duplicate_uids)
    if has_conflicts:
        changes.clear()
    if changes_out is not None:
        changes_out.extend(changes)
    if not dry_run:
        for item in changes:
            await getattr(db, item['collection']).update_one(item['key'], {'$set': item['after']}, upsert=item['before'] is None)

    return {
        'dry_run': dry_run,
        'aborted_on_conflict': has_conflicts,
        'username_keyed_count': len(username_keyed_accounts),
        'verified_uid_count': len(verified_uid_accounts),
        'duplicate_uid_count': len(duplicate_uids),
        'orphan_entitlement_count': len(orphan_entitlements),
        'unverified_active_entitlement_count': len(unverified_active_entitlements),
        'username_keyed_accounts': username_keyed_accounts,
        'verified_uid_accounts': verified_uid_accounts,
        'old_to_new_mapping': old_to_new_mapping,
        'duplicate_uids': duplicate_uids,
        'orphan_entitlements': orphan_entitlements,
        'unverified_active_entitlements': unverified_active_entitlements,
        'migrated_entitlements': migrated_entitlements if not dry_run and not has_conflicts else 0,
        'downgraded_to_pending': downgraded_pending if not dry_run and not has_conflicts else 0,
        'planned_changes': len(changes),
    }


def uid_journal(path, database, changes=None):
    """Preserve BSON dates and verify the persisted preimages before the first write."""
    path = Path(path)
    if changes is not None:
        payload = json_util.dumps({'database': database, 'changes': changes})
        envelope = {'uid_migration_version': 1, 'sha256': hashlib.sha256(payload.encode()).hexdigest(),
                    'payload': payload}
        with path.open('x', encoding='utf8') as file:
            json.dump(envelope, file)
            file.flush()
            os.fsync(file.fileno())
    envelope = json.loads(path.read_text(encoding='utf8'))
    payload = envelope['payload']
    if envelope.get('uid_migration_version') != 1 or hashlib.sha256(payload.encode()).hexdigest() != envelope['sha256']:
        raise ValueError('Invalid UID migration backup')
    data = json_util.loads(payload, json_options=json_util.JSONOptions(tz_aware=True))
    if data['database'] != database:
        raise ValueError('UID migration backup belongs to another database')
    return data['changes']


async def apply_uid_journal(db, changes, *, rollback=False, dry_run=False):
    # The snapshot, conflict check and writes use one Atlas/replica-set transaction.
    async with db.client.start_session() as session:
        async with await session.start_transaction():
            for item in reversed(changes) if rollback else changes:
                name, key = item['collection'], item['key']
                if not ((name == 'accounts_v2' and set(key) == {'locket_id'}) or
                        (name == 'entitlements' and set(key) == {'account_id', 'entitlement_key'}
                         and key['entitlement_key'] == 'Gold')):
                    raise ValueError('Invalid UID migration collection or key')
                before, after = item['before'], item['after']
                if rollback:
                    before, after = after, before
                current = await db[name].find_one(key, {'_id': 0}, session=session)
                if current == after:
                    continue
                if current != before:
                    raise RuntimeError(f'Conflicting concurrent change in {name}; transaction aborted')
                if dry_run:
                    continue
                if after is None:
                    await db[name].delete_one(key, session=session)
                else:
                    await db[name].replace_one(key, after, upsert=before is None, session=session)
                if await db[name].find_one(key, {'_id': 0}, session=session) != after:
                    raise RuntimeError('UID migration verification failed')


async def run_migration_cli(
    dry_run: bool = False,
    backup_path: str | None = None,
    verify_backup_path: str | None = None,
    rollback_path: str | None = None,
    rollback_mode: Literal['partial', 'full'] = 'partial',
    confirm_destructive: bool = False,
    reconcile: bool = False,
    uid_entitlements: bool = False,
):
    if verify_backup_path:
        info = verify_backup_file_on_disk(verify_backup_path)
        print(f"Backup verification PASSED: {json.dumps(info)}")
        return info

    settings = get_settings()
    if settings.app_env == 'staging' and settings.mongodb_database.strip() == 'locket_manager' and not dry_run:
        raise RuntimeError(
            "Refusing to run write migration/rollback against production database 'locket_manager' when APP_ENV=staging!"
        )
    client = AsyncMongoClient(
        settings.mongodb_uri.get_secret_value(),
        tz_aware=True,
        serverSelectionTimeoutMS=5000,
    )
    try:
        await client.admin.command('ping')
        db = client[settings.mongodb_database]
        if uid_entitlements:
            if rollback_path:
                changes = uid_journal(rollback_path, db.name)
                await apply_uid_journal(db, changes, rollback=True, dry_run=dry_run)
                print(f'UID rollback verified: {len(changes)} entries (dry_run={dry_run})')
                return
            changes = []
            uid_report = await inspect_and_migrate_uid_entitlements(db, changes_out=changes)
            print(f"UID Entitlement Migration report (dry_run={dry_run}): {json.dumps(uid_report)}")
            if not dry_run:
                if uid_report['aborted_on_conflict']:
                    raise RuntimeError('UID conflict; no changes applied')
                if not backup_path:
                    raise ValueError('UID migration requires --backup pointing to a new file')
                persisted = uid_journal(backup_path, db.name, changes)
                await apply_uid_journal(db, persisted)
                post = await inspect_and_migrate_uid_entitlements(db)
                if post['planned_changes'] or post['aborted_on_conflict']:
                    raise RuntimeError('Post-migration audit found outstanding changes')
                print(f'UID migration verified: {len(persisted)} entries')
                uid_report.update(dry_run=False, applied_changes=len(persisted), post_migration=post)
            return uid_report
        if reconcile:
            rec_report = await reconcile_collections(db, dry_run=dry_run)
            print(f"Reconciliation report (dry_run={dry_run}): {json.dumps(rec_report)}")
            return rec_report
        legacy_count = await db.accounts.count_documents({})
        v2_count_before = await db.accounts_v2.count_documents({})
        print(f"Connected to database '{settings.mongodb_database}'.")
        print(f"Legacy accounts count: {legacy_count} | accounts_v2 count before: {v2_count_before}")

        if backup_path:
            out_file = Path(backup_path).resolve()
            out_file.parent.mkdir(parents=True, exist_ok=True)
            snap = await export_backup_to_dict(db)
            out_file.write_text(json.dumps(snap, indent=2, default=_json_default), encoding='utf-8')
            verified_disk = verify_backup_file_on_disk(out_file)
            print(
                f"Backup written and verified on disk at {verified_disk['path']} "
                f"({verified_disk['accounts_count']} v1, {verified_disk['accounts_v2_count']} v2, "
                f"sha256={verified_disk['snapshot_sha256'][:16]}...)."
            )

        if rollback_path:
            verified_disk = verify_backup_file_on_disk(rollback_path)
            snap = json.loads(Path(verified_disk['path']).read_text(encoding='utf-8'))
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
    parser.add_argument('--backup', default=None, help='Path on persistent host/mounted volume to write JSON snapshot')
    parser.add_argument('--verify-backup', default=None, help='Verify an existing backup JSON file on disk')
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
    parser.add_argument(
        '--reconcile',
        action='store_true',
        help='Detect and repair collection drift across accounts_v2, accounts, and entitlements',
    )
    parser.add_argument(
        '--uid-entitlements',
        action='store_true',
        help='Inspect and migrate Gold entitlements to verified Firebase UID keys',
    )
    args = parser.parse_args()
    is_dry_run = args.dry_run or not (args.apply or args.rollback or args.verify_backup)
    asyncio.run(
        run_migration_cli(
            dry_run=is_dry_run,
            backup_path=args.backup,
            verify_backup_path=args.verify_backup,
            rollback_path=args.rollback,
            rollback_mode=args.mode,
            confirm_destructive=args.confirm_destructive,
            reconcile=args.reconcile,
            uid_entitlements=args.uid_entitlements,
        )
    )
