"""Opt-in real MongoDB persistence; Locket/Firebase HTTP responses remain simulated."""
import asyncio
import os
import secrets
from uuid import uuid4

from fastapi.testclient import TestClient
import httpx
from pymongo import AsyncMongoClient
from pymongo.errors import DuplicateKeyError
import pytest

from app.config import get_settings
from app.main import create_app
from app.passwords import hash_password


@pytest.mark.skipif(not os.environ.get('TEST_MONGODB_URI'), reason='Set TEST_MONGODB_URI for real MongoDB tests')
def test_authenticated_identity_persistence_and_unique_uid(monkeypatch):
    uri = os.environ['TEST_MONGODB_URI']
    database = 'locket_test_' + uuid4().hex
    password = secrets.token_urlsafe(24)
    uid = 'ActualFirebaseUidForMongoTest123'
    id_token = 'authorized-mock-id-token'
    for key, value in {
        'MONGODB_URI': uri, 'MONGODB_DATABASE': database,
        'SUPERADMIN_EMAIL': 'admin@example.test', 'SUPERADMIN_PASSWORD_HASH': hash_password(password),
        'ALLOWED_HOSTS': '["localhost"]', 'REQUIRE_HTTPS': 'false', 'NEXTDNS_ID': 'abc123',
        'ROOT_CA_PEM': '', 'ROOT_CA_PATH': '', 'LOCKET_FIREBASE_API_KEY': 'mock-project-key',
    }.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()

    def respond(request):
        if request.url.host == 'identitytoolkit.googleapis.com':
            return httpx.Response(200, json={'users': [{'localId': uid}]})
        return httpx.Response(200, json={'data': {'user': {'uid': uid, 'username': 'vt.l'}}})

    app = create_app()
    async def cleanup():
        assert database.startswith('locket_test_') and len(database) == len('locket_test_') + 32
        async with AsyncMongoClient(uri, serverSelectionTimeoutMS=5000) as client:
            await client.drop_database(database)

    try:
        with TestClient(app, base_url='http://localhost') as http:
            app.state.public_link_fetcher = lambda url: httpx.Response(
                200, text='<a href="https://locket.camera/invites/MongoTestInvite123">invite</a>',
                headers={'Content-Type': 'text/html'},
            )
            app.state.locket_api_http_client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
            try:
                login = http.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
                assert login.status_code == 200, login.text
                headers = {'Authorization': 'Bearer ' + login.json()['access_token']}
                linked = http.post('/admin/locket-session', headers=headers, json={
                    'username': 'vt.l', 'id_token': id_token,
                })
                assert linked.status_code == 200
                result = http.post('/admin/add-account', headers=headers, json={
                    'locket_id': 'vt.l', 'expires_date': '2099-01-01', 'resolve_identity': True,
                })
                assert result.status_code == 200, result.text
                assert result.json()['verification_status'] == 'verified_uid'

                async def check_database():
                    document = await app.state.accounts_v2.find_one({'locket_id': 'vt.l'})
                    assert document['firebase_uid'] == uid
                    assert document['invite_token'] == 'MongoTestInvite123'
                    assert document['_server_uid_proof'] is True
                    assert document['verification_source'] == 'owner_localid_match'
                    assert id_token not in str(document)
                    assert not {'id_token', 'refresh_token', 'idToken', 'refreshToken'} & document.keys()
                    indexes = await app.state.accounts_v2.index_information()
                    assert indexes['unique_firebase_uid_string']['unique'] is True
                    with pytest.raises(DuplicateKeyError):
                        await app.state.accounts_v2.insert_one({'locket_id': 'different.user', 'firebase_uid': uid})
                    # Multiple accounts without a UID are valid under the partial unique index.
                    await app.state.accounts_v2.insert_many([
                        {'locket_id': 'no.uid.one', 'firebase_uid': None},
                        {'locket_id': 'no.uid.two', 'firebase_uid': None},
                    ])

                http.portal.call(check_database)
                listed = http.get('/admin/accounts', headers=headers)
                assert listed.status_code == 200
                account = next(row for row in listed.json() if row['locket_id'] == 'vt.l')
                assert account['firebase_uid'] == uid
                assert account['verification_status'] == 'verified_uid'
                assert http.get('/api/accounts/lookup?query=vt.l').json() == {'exists': True}
                disconnected = http.delete('/admin/locket-session', headers=headers)
                assert disconnected.status_code == 200
            finally:
                http.portal.call(app.state.locket_api_http_client.aclose)
    finally:
        asyncio.run(cleanup())
        get_settings.cache_clear()
