import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import httpx
import pytest

from app.services.locket_authenticated_identity import (
    fetch_user_by_invite_token, resolve_and_verify_locket_uid,
    verify_target_firebase_uid, is_valid_authenticated_firebase_uid,
)
from app.services.locket_session_provider import (
    LocketSessionProvider, LocketSessionExpiredError, VerifiedOwnerProof,
)

UID = 'Abc123Def456Ghi789Jkl012Mnop'
INVITE = 'InviteToken123456789'


def run(coro):
    return asyncio.run(coro)


def provider(**kwargs):
    return LocketSessionProvider(id_token='authorized-test-token', username='vt.l', **kwargs)


def fetch(response, *, session=None):
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: response)) as client:
            return await fetch_user_by_invite_token(
                INVITE, session_provider=session or provider(), http_client=client, max_retries=1,
            )
    return run(exercise())


@pytest.mark.parametrize('envelope', [
    lambda user: {'result': {'data': {'user': user}}},
    lambda user: {'data': {'user': user}},
])
def test_authenticated_request_and_envelopes(envelope):
    async def exercise():
        def respond(req):
            assert req.method == 'POST'
            assert str(req.url) == 'https://api.locketcamera.com/fetchUserForInviteToken'
            assert req.headers['Authorization'] == 'Bearer authorized-test-token'
            assert json.loads(req.content) == {'data': {'invite_token': INVITE}}
            return httpx.Response(200, json=envelope({'uid': UID, 'username': 'vt.l'}))
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await fetch_user_by_invite_token(INVITE, session_provider=provider(), http_client=client)
    result = run(exercise())
    assert result['status'] == 'ok'
    assert result['user']['uid'] == UID


@pytest.mark.parametrize('code,status', [
    (401, 'auth_required'), (403, 'auth_required'), (404, 'not_found'),
    (429, 'rate_limited'), (500, 'lookup_unavailable'), (503, 'lookup_unavailable'),
    (302, 'invalid_response'),
])
def test_http_errors(code, status):
    assert fetch(httpx.Response(code, json={}))['status'] == status


@pytest.mark.parametrize('payload,status', [
    ({'data': {'user': {'username': 'vt.l'}}}, 'uid_missing'),
    ({'error': {'status': 'UNAUTHENTICATED'}}, 'auth_required'),
    ({'data': {'error': {'message': 'secret'}}}, 'invalid_response'),
    ({'result': {'error': 'secret'}}, 'invalid_response'),
    ([], 'invalid_response'),
])
def test_invalid_payloads(payload, status):
    assert fetch(httpx.Response(200, json=payload))['status'] == status


def test_invalid_json():
    assert fetch(httpx.Response(200, content=b'not json'))['status'] == 'invalid_response'


def test_missing_session():
    assert run(fetch_user_by_invite_token(INVITE, session_provider=None))['status'] == 'auth_required'


@pytest.mark.parametrize('invite', ['', 'bad/token', 'token?secret=1'])
def test_invalid_invite(invite):
    assert run(fetch_user_by_invite_token(invite, session_provider=provider()))['status'] == 'not_found'


def test_timeout():
    async def exercise():
        def respond(req):
            raise httpx.ReadTimeout('secret-token', request=req)
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await fetch_user_by_invite_token(INVITE, session_provider=provider(), http_client=client, max_retries=1)
    result = run(exercise())
    assert result['status'] == 'lookup_unavailable'
    assert 'secret-token' not in str(result)


def test_redirect_never_followed():
    async def exercise():
        calls = []
        def respond(req):
            calls.append(req)
            return httpx.Response(307, headers={'Location': 'https://evil.example/steal'})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond), follow_redirects=True) as client:
            result = await fetch_user_by_invite_token(INVITE, session_provider=provider(), http_client=client)
        assert len(calls) == 1
        assert result['status'] == 'invalid_response'
    run(exercise())


def test_refresh_success_and_revoke():
    session = provider(expires_in_seconds=-1, refresh_token='refresh-secret',
                       token_refresher=AsyncMock(return_value={'id_token': 'renewed-token', 'expires_in': '30'}))
    assert run(session.get_valid_token()) == 'renewed-token'
    assert session.expires_at < datetime.now(timezone.utc) + timedelta(seconds=31)
    assert 'renewed-token' not in repr(session)
    assert 'refresh-secret' not in str(session.to_safe_status())
    session.revoke()
    assert not session.is_connected


@pytest.mark.parametrize('response', [{}, {'id_token': 'new', 'expires_in': '-1'}, {'id_token': 'new', 'expires_in': 'bad'}])
def test_refresh_invalid(response):
    session = provider(expires_in_seconds=-1, refresh_token='secret', token_refresher=AsyncMock(return_value=response))
    with pytest.raises(LocketSessionExpiredError):
        run(session.get_valid_token())


def test_session_expired():
    session = provider(expires_in_seconds=-1)
    assert run(fetch_user_by_invite_token(INVITE, session_provider=session))['status'] == 'session_expired'


@pytest.mark.parametrize('uid', [INVITE, '0123456789abcdef01234567', '550e8400-e29b-41d4-a716-446655440000'])
def test_identifier_separation(uid):
    assert not is_valid_authenticated_firebase_uid(uid, invite_token=INVITE)


def test_short_authenticated_uid():
    assert is_valid_authenticated_firebase_uid('ActualUid-123')


@pytest.mark.parametrize('proof,expected', [
    (None, 'uid_resolved'),
    ({'localId': UID, 'username': 'vt.l', 'is_target_owner': True}, 'uid_resolved'),
    (VerifiedOwnerProof(UID, 'vt.l'), 'verified_uid'),
    (VerifiedOwnerProof('OtherUid-123', 'vt.l'), 'uid_resolved'),
    (VerifiedOwnerProof(UID, 'other'), 'uid_resolved'),
])
def test_owner_proof(proof, expected):
    result = run(verify_target_firebase_uid(username='vt.l', candidate_uid=UID, returned_username='vt.l', owner_identity_proof=proof))
    assert result['status'] == expected
    assert result['_server_uid_proof'] == (expected == 'verified_uid')


def test_username_mismatch():
    result = run(verify_target_firebase_uid(username='vt.l', candidate_uid=UID, returned_username='someone.else'))
    assert result['status'] == 'username_mismatch'


def test_username_required():
    assert run(verify_target_firebase_uid(username='vt.l', candidate_uid=UID))['status'] == 'invalid_response'


def test_verified_uid_conflict():
    collection = AsyncMock()
    collection.find_one.return_value = {'locket_id': 'vt.l', 'firebase_uid': 'PreviousUid-123', '_server_uid_proof': True, 'verification_status': 'verified_uid'}
    result = run(verify_target_firebase_uid(username='vt.l', candidate_uid=UID, returned_username='vt.l', accounts_v2=collection))
    assert result['status'] == 'uid_conflict'
    collection.update_one.assert_not_called()


def test_uid_owned_by_other_username_only():
    collection = AsyncMock()
    collection.find_one.side_effect = [None, None, {'username': 'other', 'firebase_uid': UID}]
    result = run(verify_target_firebase_uid(username='vt.l', candidate_uid=UID, returned_username='vt.l', accounts_v2=collection))
    assert result['status'] == 'uid_conflict'


def test_server_validates_owner_localid():
    async def exercise():
        def respond(req):
            assert req.url.host == 'identitytoolkit.googleapis.com'
            assert json.loads(req.content) == {'idToken': 'authorized-test-token'}
            return httpx.Response(200, json={'users': [{'localId': UID}]})
        session = provider(firebase_api_key='test-project-key', local_id='untrusted-imported-localid', is_target_owner=True)
        assert session.get_owner_identity_proof() is None
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            proof = await session.verify_owner_identity(http_client=client)
        assert proof.localId == UID
    run(exercise())


def test_complete_resolver_uses_existing_public_resolver():
    async def exercise():
        def respond(req):
            if req.url.host == 'identitytoolkit.googleapis.com':
                return httpx.Response(200, json={'users': [{'localId': UID}]})
            return httpx.Response(200, json={'result': {'data': {'user': {'uid': UID, 'username': 'vt.l'}}}})
        public_fetcher = AsyncMock(return_value=httpx.Response(
            200, text=f'<a href="https://locket.camera/invites/{INVITE}">invite</a>',
            headers={'Content-Type': 'text/html'},
        ))
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await resolve_and_verify_locket_uid(
                'https://locket.cam/vt.l', session_provider=provider(firebase_api_key='test-key'),
                public_fetcher=public_fetcher, http_client=client,
            )
        assert result.status == 'verified_uid'
        assert result.firebase_uid == UID
        assert result.invite_token == INVITE
        assert result.verification_source == 'owner_localid_match'
        public_fetcher.assert_awaited_once()
    run(exercise())


def test_refresh_cannot_restore_revoked_session():
    async def exercise():
        session = provider(expires_in_seconds=-1, refresh_token='secret')
        async def refresh(_):
            session.revoke()
            return {'id_token': 'renewed-token', 'expires_in': 3600}
        session._token_refresher = refresh
        with pytest.raises(LocketSessionExpiredError):
            await session.get_valid_token()
        assert not session.is_connected
    run(exercise())


def test_cached_verified_uid_does_not_require_network():
    from app.services.identity_service import resolve_locket_identity
    collection = AsyncMock()
    collection.find_one.return_value = {
        'locket_id': 'vt.l', 'firebase_uid': UID, '_server_uid_proof': True,
        'verification_status': 'verified_uid', 'verification_method': 'trusted_proof',
        'verification_source': 'owner_localid_match',
    }
    result = run(resolve_locket_identity('vt.l', accounts_v2=collection, session_provider=provider()))
    assert result.status == 'verified_uid'
    assert result.firebase_uid == UID

# Reuse the existing application fixture; its collections never contact MongoDB.
from test_account_lookup import lookup_env


def test_admin_session_import_disconnect_and_no_token_storage(lookup_env):
    http, app, accounts, accounts_v2, v1, v2, headers = lookup_env
    payload = {'username': 'vt.l', 'id_token': 'private-id-token', 'refresh_token': 'private-refresh'}
    assert http.post('/admin/locket-session', json=payload).status_code == 401
    response = http.post('/admin/locket-session', headers=headers, json=payload)
    assert response.status_code == 200
    assert 'private-' not in response.text
    assert not v1 and not v2
    linked = next(iter(app.state.locket_sessions.values()))
    assert linked.is_connected
    assert linked.get_owner_identity_proof() is None
    response = http.delete('/admin/locket-session', headers=headers)
    assert response.status_code == 200
    assert not app.state.locket_sessions
    assert not linked.is_connected
    audit_args = str(app.state.audit.insert_one.call_args_list)
    assert 'private-id-token' not in audit_args
    assert 'private-refresh' not in audit_args


def test_admin_authenticated_uid_saved_without_owner_claim(lookup_env):
    http, app, accounts, accounts_v2, v1, v2, headers = lookup_env
    from app.security import token_digest
    app.state.locket_sessions = {token_digest(headers['Authorization'].split()[1]): provider()}
    app.state.public_link_fetcher = AsyncMock(return_value=httpx.Response(
        200, text=f'<a href="https://locket.camera/invites/{INVITE}">invite</a>',
        headers={'Content-Type': 'text/html'},
    ))
    app.state.locket_api_http_client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={'data': {'user': {'uid': UID, 'username': 'vt.l'}}})
    ))
    response = http.post('/admin/add-account', headers=headers, json={
        'locket_id': 'vt.l', 'expires_date': '2027-01-01', 'resolve_identity': True,
    })
    assert response.status_code == 200, response.text
    assert v2['vt.l']['firebase_uid'] == UID
    assert v2['vt.l']['invite_token'] == INVITE
    assert v2['vt.l']['verification_status'] == 'unverified_uid'
    assert v2['vt.l']['_server_uid_proof'] is False
    assert 'authorized-test-token' not in str(v2)
    assert http.get('/api/accounts/lookup?query=vt.l').json() == {'exists': True}
    run(app.state.locket_api_http_client.aclose())

def test_admin_sessions_cannot_disconnect_each_other(lookup_env):
    from secrets import token_urlsafe
    from app.security import token_digest

    http, app, _, _, _, _, first = lookup_env
    token = token_urlsafe(48)
    second = {'Authorization': 'Bearer ' + token}
    session = dict(app.state.sessions.insert_one.call_args.args[0], _id=token_digest(token))
    run(app.state.sessions.insert_one(session))
    for headers, username in [(first, 'first.user'), (second, 'second.user')]:
        response = http.post('/admin/locket-session', headers=headers,
                             json={'username': username, 'id_token': 'test-' + username})
        assert response.status_code == 200
    a, b = app.state.locket_sessions.values()
    assert http.delete('/admin/locket-session', headers=second).status_code == 200
    assert a.is_connected and not b.is_connected
    assert http.post('/api/admin/logout', headers=first).status_code == 204
    assert not a.is_connected and not app.state.locket_sessions


def test_prompt22_admin_resolve_uid_endpoint_and_cli_no_manual_token(lookup_env, monkeypatch, capsys):
    """
    Prompt 22 Sections 5, 6, 7, 8, 9, 10 & 11:
      - Verifies GET /api/admin/locket/resolve-uid?username=vt.l (requires Admin auth, 401 without token).
      - Without backend Locket session: extracts invite_token via public link and returns status='auth_required',
        firebase_uid=None, verification_status='unverified_handle'.
      - With backend Locket session: resolves real Firebase UID via fetchUserForInviteToken, returns
        status='uid_resolved', verification_status='unverified_uid', source='authenticated_locket_api',
        and persists to accounts_v2 when persist=true.
      - When account already has a verified Firebase UID in MongoDB cache: returns immediately from cache
        with status='verified_uid', verification_status='verified_uid', cached=True.
      - CLI `python -m scripts.test_locket_uid_resolution --username vt.l --dry-run` never prompts for
        ID Token or Refresh Token in normal mode and outputs structured STATUS / USERNAME / INVITE TOKEN FOUND / FIREBASE UID / VERIFICATION / SOURCE.
    """
    from app.security import token_digest
    from scripts.test_locket_uid_resolution import main as cli_main

    http, app, accounts, accounts_v2, v1, v2, headers = lookup_env

    # 1. Requires Admin authentication
    assert http.get('/api/admin/locket/resolve-uid?username=vt.l').status_code == 401

    app.state.public_link_fetcher = AsyncMock(
        return_value=httpx.Response(
            200,
            text=f'<a href="https://locket.camera/invites/{INVITE}">vt.l</a>',
            headers={'Content-Type': 'text/html'},
        )
    )

    # 2. No backend Locket session connected -> status='auth_required', invite_token found, firebase_uid=None
    r_no_sess = http.get('/api/admin/locket/resolve-uid?username=vt.l', headers=headers)
    assert r_no_sess.status_code == 200
    d_no_sess = r_no_sess.json()
    assert d_no_sess['username'] == 'vt.l'
    assert d_no_sess['invite_token'] == INVITE
    assert d_no_sess['firebase_uid'] is None
    assert d_no_sess['status'] == 'auth_required'
    assert d_no_sess['verification_status'] == 'unverified_handle'

    # 3. Connect authorized backend Locket session -> resolves UID without any token input in the lookup request
    app.state.locket_sessions = {token_digest(headers['Authorization'].split()[1]): provider()}
    app.state.locket_api_http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json={'result': {'data': {'user': {'uid': UID, 'username': 'vt.l'}}}})
        )
    )
    try:
        r_resolved = http.get('/api/admin/locket/resolve-uid?username=https://locket.cam/vt.l&persist=true', headers=headers)
        assert r_resolved.status_code == 200
        d_res = r_resolved.json()
        assert d_res['username'] == 'vt.l'
        assert d_res['invite_token'] == INVITE
        assert d_res['firebase_uid'] == UID
        assert d_res['status'] == 'uid_resolved'
        assert d_res['verification_status'] == 'unverified_uid'
        assert d_res['source'] == 'authenticated_locket_api'
        assert d_res['cached'] is False
        assert v2['vt.l']['firebase_uid'] == UID
        assert v2['vt.l']['invite_token'] == INVITE
        assert v2['vt.l']['resolution_status'] == 'uid_resolved'
        assert v2['vt.l']['verification_status'] == 'unverified_uid'

        # 4. When account in MongoDB has a verified UID, resolve-uid returns immediately from cache
        v2['vt.l']['verification_status'] = 'verified_uid'
        v2['vt.l']['verification_method'] = 'trusted_proof'
        v2['vt.l']['verification_source'] = 'owner_localid_match'
        v2['vt.l']['_server_uid_proof'] = True

        r_cached = http.get('/api/admin/locket/resolve-uid?username=vt.l', headers=headers)
        assert r_cached.status_code == 200
        d_cached = r_cached.json()
        assert d_cached['status'] == 'verified_uid'
        assert d_cached['verification_status'] == 'verified_uid'
        assert d_cached['firebase_uid'] == UID
        assert d_cached['cached'] is True
        assert d_cached['source'] == 'owner_localid_match'

        # 5. Admin HTML includes `#searchUidBtn` ("Tìm UID") and `/api/admin/locket/resolve-uid`
        adm_html = http.get('/admin').text
        assert 'id="searchUidBtn"' in adm_html
        assert '/api/admin/locket/resolve-uid' in adm_html
    finally:
        run(app.state.locket_api_http_client.aclose())

    # 6. CLI `python -m scripts.test_locket_uid_resolution --username vt.l --dry-run` never prompts for token
    monkeypatch.delenv('LOCKET_TEST_ID_TOKEN', raising=False)
    monkeypatch.delenv('LOCKET_TEST_REFRESH_TOKEN', raising=False)
    monkeypatch.setattr(
        'scripts.test_locket_uid_resolution.resolve_public_locket_share_link',
        AsyncMock(
            return_value=type(
                'PubRes',
                (),
                {
                    'status': 'invite_token_found',
                    'normalized_id': 'vt.l',
                    'invite_token': INVITE,
                    'message': 'Đã lấy invite token.',
                },
            )()
        ),
    )
    rc = cli_main(['--username', 'vt.l', '--dry-run'])
    assert rc == 0
    out = capsys.readouterr().out
    assert 'STATUS: auth_required' in out
    assert 'USERNAME: vt.l' in out
    assert 'INVITE TOKEN FOUND: True' in out
    assert 'FIREBASE UID: None' in out
    assert 'Locket Firebase ID token:' not in out
