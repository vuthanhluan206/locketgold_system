"""Tests for public-only Add Account identity lookup."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import httpx

from app.services.locket_session_provider import LocketSessionProvider
from app.security import token_digest
from test_account_lookup import lookup_env


def test_add_account_public_only_never_uses_linked_locket_token(
    lookup_env,
):
    http, app, accounts, accounts_v2, legacy, canonical, headers = (
        lookup_env
    )

    session_id = token_digest(
        headers["Authorization"].split()[1]
    )

    linked = LocketSessionProvider(
        id_token="secret-test-token",
        username="vt.l",
    )

    app.state.locket_sessions = {
        session_id: linked
    }

    app.state.identity_provider = AsyncMock(
        side_effect=AssertionError(
            "Authenticated provider must not be used"
        )
    )

    app.state.public_link_fetcher = AsyncMock(
        return_value=httpx.Response(
            200,
            text=(
                '<a href="https://locket.camera/invites/'
                'InviteToken1234567">invite</a>'
            ),
            headers={"Content-Type": "text/html"},
        )
    )

    response = http.post(
        "/admin/add-account",
        headers=headers,
        json={
            "locket_id": "vt.l",
            "expires_date": (
                datetime.now(timezone.utc)
                + timedelta(days=30)
            ).isoformat(),
            "resolve_identity": True,
            "public_only": True,
        },
    )

    assert response.status_code == 200, response.text

    saved = response.json()

    assert saved["locket_id"] == "vt.l"
    assert saved["firebase_uid"] is None
    assert saved["verification_status"] == "unverified_handle"
    assert saved["invite_token"] == "InviteToken1234567"

    assert canonical["vt.l"]["firebase_uid"] is None

    app.state.identity_provider.assert_not_awaited()
    app.state.public_link_fetcher.assert_awaited_once()

    assert linked.is_connected


def test_add_account_has_no_locket_token_inputs():
    from pathlib import Path

    html = (
        Path(__file__).resolve().parents[1]
        / "web"
        / "index.html"
    ).read_text(encoding="utf-8")

    assert 'id="accountDialog"' in html
    assert 'id="accountId"' in html
    assert 'id="expiry"' in html

    assert "public_only: true" in html

    assert 'id="locketSessionToken"' not in html
    assert 'id="connectLocketSession"' not in html
    assert 'id="locketSessionDialog"' not in html

def test_public_only_preserves_verified_uid_when_page_has_no_uid(lookup_env):
    http, app, _, _, _, canonical, headers = lookup_env
    canonical["vt.l"] = {
        "locket_id": "vt.l", "username": "vt.l", "firebase_uid": "previously-verified-id",
        "verification_status": "verified_uid", "verification_method": "trusted_proof",
        "verification_source": "owner_localid_match", "_server_uid_proof": True,
    }
    def respond(request):
        assert request.url.host == "locket.cam"
        assert "authorization" not in request.headers and "cookie" not in request.headers
        return httpx.Response(200, text="<html>Public profile</html>", headers={"Content-Type": "text/html"})
    app.state.public_http_client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    response = http.post("/admin/add-account", headers=headers, json={
        "locket_id": "vt.l", "expires_date": "2099-01-01", "public_only": True,
    })
    assert response.status_code == 200, response.text
    assert response.json()["firebase_uid"] == "previously-verified-id"
    assert canonical["vt.l"]["_server_uid_proof"] is True
