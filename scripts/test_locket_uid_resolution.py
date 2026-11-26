"""
VPS Staging & Local CLI Verification Tool for Locket Invite Token -> Firebase UID Resolution.

Usage:
  python -m scripts.test_locket_uid_resolution --username vt.l --dry-run

Security Invariants:
  - Normal mode NEVER prompts the user to paste an ID Token or Refresh Token in the terminal.
  - Checks MongoDB `accounts_v2` cache first when `--use-cache` is enabled.
  - Uses `resolve_public_locket_share_link()` to extract `invite_token` from `https://locket.cam/<username>`.
  - Uses the configured backend `LocketSessionProvider` (if present); otherwise reports `auth_required`.
  - Never prints Bearer tokens, refresh tokens, or passwords.
  - Never modifies MongoDB when `--dry-run` is active.
  - Never fabricates or guesses a fake Firebase UID.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

from app.config import get_settings
from app.services.entitlement_service import extract_verified_uid_metadata
from app.services.identity_service import normalize_lookup_query, resolve_public_locket_share_link
from app.services.locket_authenticated_identity import resolve_and_verify_locket_uid
from app.services.locket_session_provider import LocketSessionProvider, firebase_token_refresher


def build_session_provider_from_opt_in_env() -> LocketSessionProvider | None:
    """
    Build an in-memory LocketSessionProvider ONLY if the backend environment has an authorized
    test session configured. Never prompts interactively in normal mode and never logs tokens.
    """
    id_tok = (os.environ.get('LOCKET_TEST_ID_TOKEN') or '').strip()
    ref_tok = (os.environ.get('LOCKET_TEST_REFRESH_TOKEN') or '').strip()
    local_id = (os.environ.get('LOCKET_TEST_LOCAL_ID') or '').strip() or None
    owner_user = (os.environ.get('LOCKET_TEST_USERNAME') or '').strip() or None
    is_owner = (os.environ.get('LOCKET_TEST_IS_TARGET_OWNER') or '').strip().lower() in {'1', 'true', 'yes'}
    if not id_tok and not ref_tok:
        return None
    try:
        api_key = get_settings().locket_firebase_api_key.get_secret_value()
    except Exception:
        api_key = (os.environ.get('LOCKET_FIREBASE_API_KEY') or '').strip()
    return LocketSessionProvider(
        id_token=id_tok or None,
        refresh_token=ref_tok or None,
        local_id=local_id,
        username=owner_user,
        is_target_owner=is_owner,
        firebase_api_key=api_key,
        token_refresher=firebase_token_refresher(api_key),
    )


async def _lookup_cached_account(canonical_id: str) -> dict | None:
    """Optionally query MongoDB staging `accounts_v2` for an already-cached UID."""
    try:
        from pymongo import AsyncMongoClient
        settings = get_settings()
        client = AsyncMongoClient(
            settings.mongodb_uri.get_secret_value(),
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000,
        )
        try:
            db = client[settings.mongodb_database]
            doc = await db.accounts_v2.find_one({'locket_id': canonical_id}, {'_id': 0})
            if not isinstance(doc, dict):
                doc = await db.accounts_v2.find_one({'username': canonical_id}, {'_id': 0})
            return doc if isinstance(doc, dict) else None
        finally:
            await client.close()
    except Exception:
        return None


async def run_cli(
    username: str,
    *,
    dry_run: bool = True,
    use_cache: bool = False,
) -> int:
    try:
        canonical_id, _ = normalize_lookup_query(username)
    except ValueError as exc:
        print('STATUS: invalid_link')
        print(f'USERNAME: {username}')
        print('INVITE TOKEN FOUND: False')
        print('FIREBASE UID: None')
        print('VERIFICATION: unverified')
        print('SOURCE: none')
        print(f'MESSAGE: {exc}')
        return 1

    if use_cache:
        cached_doc = await _lookup_cached_account(canonical_id)
        if isinstance(cached_doc, dict) and cached_doc.get('firebase_uid'):
            fb_uid, is_ver, ver_status, _, ver_source = extract_verified_uid_metadata(cached_doc)
            if fb_uid:
                print(f'STATUS: {"verified_uid" if is_ver else "uid_resolved"}')
                print(f'USERNAME: {cached_doc.get("username") or canonical_id}')
                print(f'INVITE TOKEN FOUND: {bool(cached_doc.get("invite_token"))}')
                print(f'FIREBASE UID: {fb_uid}')
                print(f'VERIFICATION: {ver_status}')
                print(f'SOURCE: mongodb_cache ({ver_source})')
                return 0

    session_provider = build_session_provider_from_opt_in_env()
    if session_provider is None or not session_provider.is_connected:
        pub_res = await resolve_public_locket_share_link(username)
        has_invite = bool(pub_res.invite_token)
        if has_invite:
            print('STATUS: auth_required')
            print(f'USERNAME: {pub_res.normalized_id}')
            print('INVITE TOKEN FOUND: True')
            print('FIREBASE UID: None')
            print('VERIFICATION: unverified_handle')
            print('SOURCE: public_share_link')
            print('MESSAGE: Nguồn tra cứu UID yêu cầu phiên xác thực hợp lệ.')
            return 0
        print(f'STATUS: {pub_res.status}')
        print(f'USERNAME: {pub_res.normalized_id}')
        print('INVITE TOKEN FOUND: False')
        print('FIREBASE UID: None')
        print('VERIFICATION: unverified_handle')
        print('SOURCE: public_share_link')
        print(f'MESSAGE: {pub_res.message}')
        return 1

    res = await resolve_and_verify_locket_uid(
        username,
        session_provider=session_provider,
    )
    has_invite = bool(res.invite_token)
    if res.status == 'verified_uid' and res.firebase_uid:
        print('STATUS: verified_uid')
        print(f'USERNAME: {res.username or res.normalized_id}')
        print(f'INVITE TOKEN FOUND: {has_invite}')
        print(f'FIREBASE UID: {res.firebase_uid}')
        print('VERIFICATION: verified_uid')
        print(f'SOURCE: {res.verification_source}')
        return 0

    if res.status == 'uid_resolved' and res.firebase_uid:
        print('STATUS: uid_resolved')
        print(f'USERNAME: {res.username or res.normalized_id}')
        print(f'INVITE TOKEN FOUND: {has_invite}')
        print(f'FIREBASE UID: {res.firebase_uid}')
        print('VERIFICATION: unverified_uid')
        print('SOURCE: authenticated_locket_api')
        print('MESSAGE: Cần xác minh quyền sở hữu tài khoản.')
        return 0

    print(f'STATUS: {res.status}')
    print(f'USERNAME: {res.username or res.normalized_id}')
    print(f'INVITE TOKEN FOUND: {has_invite}')
    print('FIREBASE UID: None')
    print(f'VERIFICATION: {res.verification_status}')
    print(f'SOURCE: {res.identity_lookup_source or "locket_invite_lookup"}')
    print(f'MESSAGE: {res.message}')
    return 0 if res.status == 'auth_required' else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='Verify Locket public invite token & authenticated Firebase UID resolution without manual token prompts.'
    )
    parser.add_argument('--username', required=True, help='Locket username or https://locket.cam/<username> share link')
    parser.add_argument('--dry-run', action='store_true', default=True, help='Run in read-only dry-run mode (no MongoDB writes)')
    parser.add_argument('--use-cache', action='store_true', default=False, help='Check MongoDB accounts_v2 cache before querying network')
    args = parser.parse_args(argv)
    return asyncio.run(run_cli(args.username, dry_run=args.dry_run, use_cache=args.use_cache))


if __name__ == '__main__':
    sys.exit(main())
