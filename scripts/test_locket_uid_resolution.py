"""
VPS Staging & Local CLI Verification Tool for Locket Invite Token -> Firebase UID Resolution.

Usage:
  python -m scripts.test_locket_uid_resolution --username vt.l --dry-run

Security Invariants:
  - Uses `resolve_public_locket_share_link()` to extract `invite_token` from `https://locket.cam/<username>`.
  - Checks if an authorized Locket test session is provided (via optional environment/prompts in memory only).
  - Never prints Bearer tokens, refresh tokens, or passwords.
  - Never modifies MongoDB when `--dry-run` is active.
  - Never fabricates or guesses a fake Firebase UID.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from getpass import getpass

from app.services.identity_service import resolve_public_locket_share_link
from app.services.locket_authenticated_identity import resolve_and_verify_locket_uid
from app.services.locket_session_provider import LocketSessionProvider, firebase_token_refresher
from app.config import get_settings


def build_session_provider_from_opt_in_env() -> LocketSessionProvider | None:
    """
    Build an in-memory LocketSessionProvider ONLY if the operator has explicitly provided
    an opt-in test session in memory/environment for the test run.
    Never logs or prints any token values.
    """
    id_tok = (os.environ.get('LOCKET_TEST_ID_TOKEN') or '').strip()
    ref_tok = (os.environ.get('LOCKET_TEST_REFRESH_TOKEN') or '').strip()
    local_id = (os.environ.get('LOCKET_TEST_LOCAL_ID') or '').strip() or None
    owner_user = (os.environ.get('LOCKET_TEST_USERNAME') or '').strip() or None
    is_owner = (os.environ.get('LOCKET_TEST_IS_TARGET_OWNER') or '').strip().lower() in {'1', 'true', 'yes'}
    if not id_tok and not ref_tok:
        return None
    api_key = get_settings().locket_firebase_api_key.get_secret_value()
    return LocketSessionProvider(
        id_token=id_tok or None,
        refresh_token=ref_tok or None,
        local_id=local_id,
        username=owner_user,
        is_target_owner=is_owner,
        firebase_api_key=api_key,
        token_refresher=firebase_token_refresher(api_key),
    )


async def run_cli(username: str, *, dry_run: bool = True, import_session: bool = False) -> int:
    if import_session:
        api_key = get_settings().locket_firebase_api_key.get_secret_value()
        session_provider = LocketSessionProvider(
            id_token=getpass('Locket Firebase ID token: '),
            refresh_token=getpass('Refresh token (optional): ') or None,
            username=username, firebase_api_key=api_key,
            token_refresher=firebase_token_refresher(api_key),
        )
    else:
        session_provider = build_session_provider_from_opt_in_env()
    if session_provider is None or not session_provider.is_connected:
        pub_res = await resolve_public_locket_share_link(username)
        has_invite = bool(pub_res.invite_token)
        if has_invite:
            print('STATUS: auth_required')
            print(f'USERNAME: {pub_res.normalized_id}')
            print('INVITE TOKEN FOUND: True')
            print('FIREBASE UID: None')
            print('VERIFICATION: unverified')
            print('MESSAGE: Chưa có phiên Locket hợp lệ để tra cứu UID.')
            return 0
        print(f'STATUS: {pub_res.status}')
        print(f'USERNAME: {pub_res.normalized_id}')
        print('INVITE TOKEN FOUND: False')
        print('FIREBASE UID: None')
        print('VERIFICATION: unverified')
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
        print('VERIFICATION: verified')
        print(f'SOURCE: {res.verification_source}')
        return 0

    if res.status == 'uid_resolved' and res.firebase_uid:
        print('STATUS: uid_resolved')
        print(f'USERNAME: {res.username or res.normalized_id}')
        print(f'INVITE TOKEN FOUND: {has_invite}')
        print(f'FIREBASE UID: {res.firebase_uid}')
        print('VERIFICATION: unverified')
        print('MESSAGE: Cần xác minh quyền sở hữu tài khoản.')
        return 0

    print(f'STATUS: {res.status}')
    print(f'USERNAME: {res.username or res.normalized_id}')
    print(f'INVITE TOKEN FOUND: {has_invite}')
    print('FIREBASE UID: None')
    print('VERIFICATION: unverified')
    print(f'MESSAGE: {res.message}')
    return 0 if res.status == 'auth_required' else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='Verify Locket public invite token & authenticated Firebase UID resolution without modifying production data.'
    )
    parser.add_argument('--username', required=True, help='Locket username or https://locket.cam/<username> share link')
    parser.add_argument('--dry-run', action='store_true', default=True, help='Run in read-only dry-run mode (no MongoDB writes)')
    parser.add_argument('--import-session', action='store_true', help='Read an authorized test session using hidden prompts; never persist it')
    args = parser.parse_args(argv)
    return asyncio.run(run_cli(args.username, dry_run=args.dry_run, import_session=args.import_session))


if __name__ == '__main__':
    sys.exit(main())
