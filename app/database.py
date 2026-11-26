from contextlib import asynccontextmanager
from datetime import datetime, timezone
import asyncio
import hashlib
import logging
import re
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography import x509
from fastapi import FastAPI, Request
from pymongo import AsyncMongoClient
from .config import get_settings
from .models import ACCOUNT_ID_REGEX, compute_entitlement_status, normalize_expiry
from .profile import build_profile

logger = logging.getLogger(__name__)


def admin_document(settings):
    password_hash = settings.superadmin_password_hash.get_secret_value()
    return {
        'email': settings.superadmin_email,
        'password_hash': password_hash,
        'auth_version': hashlib.sha256(password_hash.encode('ascii')).hexdigest(),
    }


async def _fetch_all_documents(collection, query: dict | None = None, projection: dict | None = None) -> list[dict]:
    """Read all documents from a collection without a hard 10,000-record truncation cap."""
    find_fn = getattr(collection, 'find', None)
    if find_fn is None:
        return []
    cursor = find_fn(query or {}, projection or {'_id': 0})
    to_list_fn = getattr(cursor, 'to_list', None)
    if to_list_fn is not None:
        res = to_list_fn(length=None)
        if asyncio.iscoroutine(res):
            docs = await res
            return [d for d in docs if isinstance(d, dict)] if isinstance(docs, list) else []
    if hasattr(cursor, '__aiter__'):
        docs = []
        async for item in cursor:
            if isinstance(item, dict):
                docs.append(item)
        return docs
    return []


async def run_controlled_migration(db, *, dry_run: bool = True) -> dict:
    """
    Controlled, explicit migration from legacy `accounts` into `accounts_v2`.
    NEVER runs automatically during FastAPI application startup.
    Reports detailed counts: inserted, skipped, invalid, conflict, and details list.
    """
    now = datetime.now(timezone.utc)
    report = {
        'dry_run': dry_run,
        'timestamp': now.isoformat(),
        'total_legacy': 0,
        'inserted': 0,
        'skipped': 0,
        'invalid': 0,
        'conflict': 0,
        'invalid_records': [],
        'conflict_records': [],
    }

    legacy_docs = await _fetch_all_documents(getattr(db, 'accounts', None), {}, {'_id': 0})
    report['total_legacy'] = len(legacy_docs)

    v2_map: dict[str, dict] = {}
    v2_list = await _fetch_all_documents(getattr(db, 'accounts_v2', None), {}, {'_id': 0})
    for item in v2_list:
        if isinstance(item.get('locket_id'), str):
            v2_map[item['locket_id']] = item

    seen_ids: set[str] = set()
    for idx, doc in enumerate(legacy_docs):
        if not isinstance(doc, dict):
            report['invalid'] += 1
            report['invalid_records'].append({'index': idx, 'reason': 'Not a BSON dictionary'})
            continue
        lid = doc.get('locket_id') or doc.get('account_id') or doc.get('uid')
        if not isinstance(lid, str) or not re.fullmatch(ACCOUNT_ID_REGEX, lid):
            report['invalid'] += 1
            report['invalid_records'].append({'index': idx, 'locket_id': str(lid), 'reason': 'Missing or invalid locket_id'})
            continue
        if lid in seen_ids:
            report['conflict'] += 1
            report['conflict_records'].append({'locket_id': lid, 'reason': 'Duplicate locket_id in legacy collection'})
            continue
        seen_ids.add(lid)

        raw_exp = doc.get('expires_date') if 'expires_date' in doc else (
            doc.get('expires_at') or doc.get('gold_expires_at')
        )
        try:
            expiry = normalize_expiry(raw_exp)
        except Exception:
            report['invalid'] += 1
            report['invalid_records'].append({'locket_id': lid, 'reason': 'Missing or unparseable expiry date'})
            continue

        status, _ = compute_entitlement_status({'locket_id': lid, 'expires_date': expiry, 'status': doc.get('status'), 'is_active': doc.get('is_active')}, now)
        mapped_status = 'revoked' if status == 'revoked' else ('active' if status == 'active' else 'expired')

        if lid in v2_map:
            existing_v2 = v2_map[lid]
            try:
                v2_exp = normalize_expiry(existing_v2.get('expires_date'))
            except Exception:
                v2_exp = None
            if v2_exp == expiry and existing_v2.get('status') == mapped_status:
                report['skipped'] += 1
            else:
                # Never overwrite newer or diverged v2 data
                report['conflict'] += 1
                report['conflict_records'].append({
                    'locket_id': lid,
                    'reason': 'Existing accounts_v2 record has different expiry or status; preserved v2 record',
                })
            continue

        new_v2_doc = {
            'schema_version': 2,
            'account_id': lid,
            'locket_id': lid,
            'username': doc.get('username'),
            'source_link': doc.get('source_link'),
            'verification_status': doc.get('verification_status', 'manual_lab_id'),
            'verification_method': doc.get('verification_method', 'admin_manual_override'),
            'status': mapped_status,
            'product_identifier': 'com.locket.gold.yearly',
            'purchase_date': now,
            'expires_date': expiry,
            'revoked_at': now if mapped_status == 'revoked' else None,
            'revoke_reason': 'Migrated revoked state' if mapped_status == 'revoked' else None,
            'max_devices': int(doc.get('max_devices') or 2),
            'notes': 'Migrated from legacy accounts collection',
            'created_at': now,
            'updated_at': now,
        }
        if not dry_run:
            await db.accounts_v2.update_one(
                {'locket_id': lid},
                {'$setOnInsert': new_v2_doc},
                upsert=True,
            )
        report['inserted'] += 1

    return report


async def sync_legacy_accounts_to_v2(db) -> int:
    """Backward-compatible helper for explicit CLI migration calls."""
    rep = await run_controlled_migration(db, dry_run=False)
    return rep['inserted']


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.profile = None
    try:
        has_dns = bool(settings.nextdns_id or getattr(settings, 'doh_server_url', ''))
        app.state.profile = build_profile(settings) if has_dns else None
    except (ValueError, OSError, x509.ExtensionNotFound, InvalidSignature, UnsupportedAlgorithm) as exc:
        logger.error('PROFILE_CONFIG_INVALID: %s; profile download disabled', type(exc).__name__)
    client = AsyncMongoClient(
        settings.mongodb_uri.get_secret_value(),
        tz_aware=True,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        socketTimeoutMS=5000,
        timeoutMS=5000,
        maxPoolSize=20,
    )
    try:
        await client.admin.command('ping')
        db = client[settings.mongodb_database]
        app.state.mongo_client = client
        app.state.db = db
        app.state.accounts = db.accounts
        app.state.admins = db.admins
        app.state.sessions = db.sessions
        app.state.login_limits = db.login_limits
        app.state.viewers_history = db.viewers_history

        await app.state.accounts.create_index('locket_id', unique=True)
        await db.admins.create_index('email', unique=True)
        await db.sessions.create_index('expires_at', expireAfterSeconds=0)
        await db.login_limits.create_index('expires_at', expireAfterSeconds=0)
        await db.viewers_history.create_index([('token', 1), ('viewed_at', -1)])

        # New v2 collections for Research Lab
        app.state.accounts_v2 = getattr(db, 'accounts_v2', None)
        app.state.devices = getattr(db, 'devices', None)
        app.state.entitlements = getattr(db, 'entitlements', None)
        app.state.audit = getattr(db, 'audit', None)
        app.state.lab_requests = getattr(db, 'lab_requests', None)
        app.state.test_results = getattr(db, 'test_results', None)
        app.state.profile_versions = getattr(db, 'profile_versions', None)
        app.state.download_tickets = getattr(db, 'download_tickets', None)

        # Mandatory unique & TTL indexes for canonical v2 collections (never silently ignore failures!)
        for col_name, idx_spec, idx_kwargs in [
            ('accounts_v2', 'locket_id', {'unique': True}),
            ('accounts_v2', 'username', {'sparse': True}),
            ('accounts_v2', 'firebase_uid', {'sparse': True}),
            ('accounts_v2', 'firebase_uid', {
                'name': 'unique_firebase_uid_string', 'unique': True,
                'partialFilterExpression': {'firebase_uid': {'$type': 'string'}},
            }),
            ('devices', 'device_id', {'unique': True}),
            ('devices', 'token_hash', {'unique': True}),
            (
                'devices',
                [('locket_id', 1), ('slot_index', 1)],
                {'unique': True, 'partialFilterExpression': {'status': 'active', 'slot_index': {'$type': 'number'}}},
            ),
            ('entitlements', [('account_id', 1), ('entitlement_key', 1)], {'unique': True}),
            ('download_tickets', 'ticket_hash', {'unique': True}),
            ('download_tickets', 'expires_at', {'expireAfterSeconds': 0}),
            ('audit', [('timestamp', -1)], {}),
            ('lab_requests', 'timestamp', {'expireAfterSeconds': 604800}),
        ]:
            col = getattr(db, col_name, None)
            if col is not None and hasattr(col, 'create_index'):
                try:
                    res = col.create_index(idx_spec, **idx_kwargs)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception as exc:
                    logger.error(
                        'MONGODB_INDEX_CREATION_FAILED: collection=%s error=%s',
                        col_name,
                        type(exc).__name__,
                    )
                    raise

        await db.admins.update_one(
            {'_id': 'superadmin'},
            {'$setOnInsert': admin_document(settings)},
            upsert=True,
        )
        # NOTE: Startup does NOT automatically mutate or migrate `accounts` to `accounts_v2`.
        # Migration is strictly controlled via `python -m scripts.migrate_db`.
        yield
    finally:
        await client.close()


def get_accounts(request: Request):
    return request.app.state.accounts
