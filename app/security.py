import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from pymongo import ReturnDocument
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from .config import get_settings
from .middleware import client_ip
from .services.device_service import verify_device_token

bearer = HTTPBearer(auto_error=False)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


async def require_subscriber_access(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
):
    unauthorized = HTTPException(
        401,
        "Invalid or missing subscriber API token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized

    raw_cred = credentials.credentials
    settings = get_settings()
    configured = settings.subscriber_api_token
    if configured is not None and secrets.compare_digest(
        raw_cred.encode("utf-8"),
        configured.get_secret_value().encode("ascii"),
    ):
        request.state.caller_kind = "service_token"
        return

    # Support enrolled Lab Device tokens (lkg_dev_*)
    if raw_cred.startswith("lkg_dev_"):
        device_doc = await verify_device_token(request, raw_cred)
        if device_doc is not None:
            target_account_id = request.path_params.get("account_id")
            allowed_ids = {
                device_doc.get("locket_id"),
                device_doc.get("firebase_uid"),
                device_doc.get("canonical_locket_id"),
            } - {None, ""}
            if target_account_id is not None and target_account_id not in allowed_ids:
                raise HTTPException(
                    403,
                    "Device token is not authorized to access this account",
                )
            request.state.caller_kind = "device_token"
            request.state.device_doc = device_doc
            return

    if re.fullmatch(r"[A-Za-z0-9_-]{64}", raw_cred):
        sessions = getattr(request.app.state, "sessions", None)
        admins = getattr(request.app.state, "admins", None)
        if sessions is not None and admins is not None:
            session = await sessions.find_one({
                "_id": token_digest(raw_cred),
                "expires_at": {"$gt": datetime.now(timezone.utc)},
            })
            if session is not None and session.get("admin_id") == "superadmin":
                admin = await admins.find_one({"_id": session["admin_id"]})
                if admin is not None and admin.get("auth_version") == session.get("auth_version"):
                    request.state.caller_kind = "admin_session"
                    return

    raise unauthorized


async def require_admin(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
):
    now = datetime.now(timezone.utc)
    ip_key = hashlib.sha256(client_ip(request.scope).encode('utf-8')).hexdigest()
    bucket = await request.app.state.login_limits.find_one_and_update(
        {'_id': f'admin:{int(now.timestamp()) // 60}:{ip_key}'},
        {'$inc': {'count': 1}, '$setOnInsert': {'expires_at': now + timedelta(minutes=2)}},
        upsert=True, return_document=ReturnDocument.AFTER,
    )
    if bucket['count'] > 60:
        raise HTTPException(429, 'Too many admin requests', headers={'Retry-After': '60'})
    unauthorized = HTTPException(401, "Invalid or expired session", headers={"WWW-Authenticate": "Bearer"})
    if credentials is None or not re.fullmatch(r"[A-Za-z0-9_-]{64}", credentials.credentials):
        raise unauthorized
    session = await request.app.state.sessions.find_one({
        "_id": token_digest(credentials.credentials),
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    })
    if session is None or session.get("admin_id") != "superadmin":
        raise unauthorized
    admin = await request.app.state.admins.find_one({"_id": session["admin_id"]})
    if admin is None or admin.get("auth_version") != session["auth_version"]:
        raise unauthorized
    return {"session_id": session["_id"], "email": admin["email"]}
