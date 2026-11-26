from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VerifiedOwnerProof:
    localId: str
    username: str
    is_target_owner: bool = True


class LocketAuthRequiredError(Exception):
    """Raised when no Locket session has been connected to LocketSessionProvider."""


class LocketSessionExpiredError(Exception):
    """Raised when the Locket ID token is expired and cannot be refreshed."""


def firebase_token_refresher(api_key: str):
    async def refresh_token(token: str) -> dict:
        from httpx import AsyncClient
        if not api_key:
            raise LocketSessionExpiredError('Firebase API key is not configured.')
        async with AsyncClient(timeout=8.0, follow_redirects=False) as client:
            response = await client.post(
                'https://securetoken.googleapis.com/v1/token', params={'key': api_key},
                data={'grant_type': 'refresh_token', 'refresh_token': token},
            )
        if response.status_code != 200:
            raise LocketSessionExpiredError('Firebase rejected session refresh.')
        return response.json()
    return refresh_token


class LocketSessionProvider:
    """
    In-memory, security-hardened Locket/Firebase test session manager.
    Security Invariants:
      - Completely separated from website Admin authentication tokens.
      - Never writes plaintext ID tokens or refresh tokens to disk, MongoDB, logs, or responses.
      - Checks token expiration and refreshes via an injected/authorized refresher when needed.
      - Supports immediate session revocation and memory wipe (`revoke()`).
    """

    def __init__(
        self,
        *,
        id_token: str | None = None,
        refresh_token: str | None = None,
        local_id: str | None = None,
        username: str | None = None,
        expires_at: datetime | None = None,
        expires_in_seconds: int = 3600,
        token_refresher: Callable[[str], Any] | None = None,
        is_target_owner: bool = False,
        firebase_api_key: str = '',
    ) -> None:
        self._id_token: str | None = None
        self._firebase_api_key = firebase_api_key
        self._generation = 0
        self._refresh_lock = asyncio.Lock()
        self._refresh_token: str | None = None
        self._local_id: str | None = None
        self._username: str | None = None
        self._expires_at: datetime | None = None
        self._token_refresher: Callable[[str], Any] | None = token_refresher
        self._is_target_owner: bool = bool(is_target_owner)

        if id_token or refresh_token:
            self.set_session(
                id_token=id_token,
                refresh_token=refresh_token,
                local_id=local_id,
                username=username,
                expires_at=expires_at,
                expires_in_seconds=expires_in_seconds,
                token_refresher=token_refresher,
                is_target_owner=is_target_owner,
            )

    def __repr__(self) -> str:
        return (
            f"<LocketSessionProvider connected={self.is_connected} "
            f"local_id={self._local_id!r} expired={self.is_expired}>"
        )

    @property
    def is_connected(self) -> bool:
        return bool(self._id_token or self._refresh_token)

    @property
    def local_id(self) -> str | None:
        return self._local_id

    @property
    def username(self) -> str | None:
        return self._username

    @property
    def is_target_owner(self) -> bool:
        return self._is_target_owner

    @property
    def expires_at(self) -> datetime | None:
        return self._expires_at

    @property
    def is_expired(self) -> bool:
        if not self._id_token or self._expires_at is None:
            return True
        now = datetime.now(timezone.utc)
        return now >= self._expires_at

    def set_session(
        self,
        *,
        id_token: str | None = None,
        refresh_token: str | None = None,
        local_id: str | None = None,
        username: str | None = None,
        expires_at: datetime | None = None,
        expires_in_seconds: int = 3600,
        token_refresher: Callable[[str], Any] | None = None,
        is_target_owner: bool = False,
    ) -> None:
        clean_id = id_token.strip() if isinstance(id_token, str) and id_token.strip() else None
        clean_ref = refresh_token.strip() if isinstance(refresh_token, str) and refresh_token.strip() else None
        if clean_id and clean_id.startswith('lkg_'):
            raise ValueError('Website Admin or Device tokens must never be used as a Locket Firebase session token.')
        self._generation += 1
        self._id_token = clean_id
        self._refresh_token = clean_ref
        self._local_id = local_id.strip() if isinstance(local_id, str) and local_id.strip() else None
        self._username = username.strip().removeprefix('@') if isinstance(username, str) and username.strip() else None
        if expires_at is not None:
            self._expires_at = (
                expires_at.astimezone(timezone.utc)
                if expires_at.tzinfo is not None
                else expires_at.replace(tzinfo=timezone.utc)
            )
        elif clean_id is not None:
            self._expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in_seconds))
        else:
            self._expires_at = None
        if token_refresher is not None:
            self._token_refresher = token_refresher
        self._is_target_owner = bool(is_target_owner)

    def revoke(self) -> None:
        """Immediately wipe all sensitive session tokens and identity state from memory."""
        self._generation += 1
        self._id_token = None
        self._refresh_token = None
        self._local_id = None
        self._username = None
        self._expires_at = None
        self._is_target_owner = False

    def get_owner_identity_proof(self) -> dict | None:
        """
        Return non-sensitive owner proof metadata if this session belongs to a verified target owner.
        Never includes raw tokens.
        """
        return None  # Imported localId and owner flags are not server evidence.

    async def verify_owner_identity(self, *, http_client=None) -> VerifiedOwnerProof | None:
        from httpx import AsyncClient, HTTPError
        if not self._firebase_api_key or not self._username:
            return None
        generation = self._generation
        try:
            token = await self.get_valid_token()
            async def lookup(client):
                return await client.post(
                    'https://identitytoolkit.googleapis.com/v1/accounts:lookup',
                    params={'key': self._firebase_api_key}, json={'idToken': token},
                    timeout=8.0, follow_redirects=False,
                )
            if http_client is not None:
                response = await lookup(http_client)
            else:
                async with AsyncClient() as client:
                    response = await lookup(client)
            if response.status_code != 200 or generation != self._generation:
                return None
            payload = response.json()
            users = payload.get('users') if isinstance(payload, dict) else None
            if not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], dict):
                return None
            uid = users[0].get('localId')
            if not isinstance(uid, str) or not uid or users[0].get('disabled'):
                return None
            return VerifiedOwnerProof(localId=uid, username=self._username)
        except (HTTPError, ValueError, LocketAuthRequiredError, LocketSessionExpiredError):
            return None

    def to_safe_status(self) -> dict:
        """Return redacted session metadata safe for Admin diagnostics and logs."""
        return {
            'connected': self.is_connected,
            'expired': self.is_expired if self.is_connected else False,
            'local_id': self._local_id,
            'username': self._username,
            'is_target_owner': self._is_target_owner,
            'expires_at': self._expires_at.isoformat() if self._expires_at else None,
        }

    async def refresh(self) -> str:
        """Refresh the Firebase ID token using the configured token_refresher without logging tokens."""
        if not self._refresh_token:
            raise LocketSessionExpiredError('Phiên Locket đã hết hạn và không có refresh token (session_expired).')
        if self._token_refresher is None:
            raise LocketSessionExpiredError('Phiên Locket đã hết hạn và chưa cấu hình cơ chế làm mới phiên (session_expired).')
        generation = self._generation
        try:
            res = self._token_refresher(self._refresh_token)
            if asyncio.iscoroutine(res) or hasattr(res, '__await__'):
                res = await asyncio.wait_for(res, timeout=8.0)
        except LocketSessionExpiredError:
            raise
        except Exception as exc:
            logger.warning('LOCKET_SESSION_REFRESH_FAILED: %s', type(exc).__name__)
            raise LocketSessionExpiredError('Không thể làm mới phiên Locket: refresh token đã hết hạn hoặc bị thu hồi (session_expired).') from exc

        if not isinstance(res, dict):
            raise LocketSessionExpiredError('Phản hồi làm mới phiên Locket không hợp lệ (session_expired).')

        new_token = res.get('id_token') or res.get('idToken') or res.get('access_token')
        if not isinstance(new_token, str) or not new_token.strip():
            raise LocketSessionExpiredError('Không nhận được ID token mới khi làm mới phiên Locket (session_expired).')

        if generation != self._generation or new_token.strip().startswith('lkg_'):
            raise LocketSessionExpiredError('Session revoked or invalid refresh response.')
        try:
            expires_in = int(res.get('expires_in') or res.get('expiresIn') or 3600)
        except (TypeError, ValueError):
            raise LocketSessionExpiredError('Invalid session expiration.') from None
        if not 0 < expires_in <= 3600:
            raise LocketSessionExpiredError('Refreshed session already expired.')
        self._id_token = new_token.strip()
        new_refresh = res.get('refresh_token') or res.get('refreshToken')
        if isinstance(new_refresh, str) and new_refresh.strip():
            self._refresh_token = new_refresh.strip()
        new_uid = res.get('user_id') or res.get('localId') or res.get('uid')
        if isinstance(new_uid, str) and new_uid.strip():
            self._local_id = new_uid.strip()
        self._expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        return self._id_token

    async def get_valid_token(self) -> str:
        """Return a non-expired Firebase ID token, refreshing automatically if expired."""
        if not self.is_connected:
            raise LocketAuthRequiredError('Chưa có phiên Locket hợp lệ để tra cứu UID (auth_required).')
        if not self._id_token or self.is_expired:
            async with self._refresh_lock:
                if not self.is_connected:
                    raise LocketAuthRequiredError('Session disconnected.')
                if not self._id_token or self.is_expired:
                    return await self.refresh()
        return self._id_token
