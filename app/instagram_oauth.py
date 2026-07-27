# =============================================================================
# app/instagram_oauth.py
# -----------------------------------------------------------------------------
# Rebuilt on "Instagram API with Instagram Login" instead of Facebook Login
# for Business. The account logs into Instagram directly — no Facebook Page,
# no /me/accounts lookup, no pages_manage_metadata permission fight. This is
# exactly the product configured on the App Dashboard's "Instagram Business"
# use case page (the one showing Instagram accounts + Generate token +
# Webhook Subscription toggle directly, with no Page anywhere in sight).
#
#   GET /api/instagram/oauth/start-url   (protected)
#   GET /api/instagram/oauth/callback    (public — Instagram redirects here)
#   DELETE /api/instagram/oauth/disconnect  (protected)
#   send_instagram_dm(...)
#
# Same signed-state reasoning as before: state must be unforgeable, or
# someone could hijack another user's connection via a crafted callback URL.
# =============================================================================
import logging
import time

import httpx
import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from supabase import Client

from app.auth import verify_jwt_and_get_user_id
from app.config import get_settings, get_supabase_admin_client

logger = logging.getLogger("dm_trigger_bot")

router = APIRouter(prefix="/api/instagram/oauth", tags=["instagram-oauth"])

# Note the different hosts: authorization + short-lived token exchange use
# api.instagram.com, everything AFTER you have a token uses graph.instagram.com.
# Mixing these up is a common source of "Cannot parse access token" errors.
INSTAGRAM_OAUTH_DIALOG = "https://api.instagram.com/oauth/authorize"
INSTAGRAM_TOKEN_EXCHANGE = "https://api.instagram.com/oauth/access_token"
INSTAGRAM_LONG_LIVED_EXCHANGE = "https://graph.instagram.com/access_token"
INSTAGRAM_GRAPH = "https://graph.instagram.com/v21.0"

# instagram_business_basic: read the account's own profile/ID.
# instagram_business_manage_messages: send/receive DMs — the permission
# that actually matters for this product.
SCOPES = "instagram_business_basic,instagram_business_manage_messages"


def _make_state(user_id: str) -> str:
    settings = get_settings()
    return pyjwt.encode(
        {"user_id": user_id, "exp": int(time.time()) + 600},
        settings.OAUTH_STATE_SECRET,
        algorithm="HS256",
    )


def _read_state(state: str) -> str:
    settings = get_settings()
    try:
        payload = pyjwt.decode(state, settings.OAUTH_STATE_SECRET, algorithms=["HS256"])
    except pyjwt.PyJWTError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired OAuth state")
    return payload["user_id"]


@router.get("/start-url")
def get_start_url(user_id: str = Depends(verify_jwt_and_get_user_id)):
    settings = get_settings()
    state = _make_state(user_id)

    params = {
        "client_id": settings.FACEBOOK_APP_ID,  # this is your Instagram App ID from the same App Dashboard
        "redirect_uri": settings.INSTAGRAM_REDIRECT_URI,
        "state": state,
        "scope": SCOPES,
        "response_type": "code",
    }
    query = "&".join(f"{k}={httpx.QueryParams({k: v})[k]}" for k, v in params.items())
    return {"url": f"{INSTAGRAM_OAUTH_DIALOG}?{query}"}


@router.get("/callback")
def oauth_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: Client = Depends(get_supabase_admin_client),
):
    settings = get_settings()
    user_id = _read_state(state)

    try:
        with httpx.Client(timeout=10) as client:
            # 1. Exchange the code for a short-lived token. Note this is a
            #    POST with form data, not query params like Facebook's flow.
            token_res = client.post(
                INSTAGRAM_TOKEN_EXCHANGE,
                data={
                    "client_id": settings.FACEBOOK_APP_ID,
                    "client_secret": settings.FACEBOOK_APP_SECRET,
                    "grant_type": "authorization_code",
                    "redirect_uri": settings.INSTAGRAM_REDIRECT_URI,
                    "code": code,
                },
            )
            if token_res.status_code != 200:
                logger.error("Instagram token exchange failed: %s", token_res.text)
                return RedirectResponse(f"{settings.FRONTEND_URL}/dashboard?instagram=error")

            token_data = token_res.json()
            short_lived_token = token_data["access_token"]
            # This IS the Instagram Business Account's own ID — no Page
            # lookup step needed at all, unlike the old Facebook Login flow.
            ig_account_id = str(token_data["user_id"])

            # 2. Exchange for a long-lived token (60 days instead of ~1 hour).
            long_res = client.get(
                INSTAGRAM_LONG_LIVED_EXCHANGE,
                params={
                    "grant_type": "ig_exchange_token",
                    "client_secret": settings.FACEBOOK_APP_SECRET,
                    "access_token": short_lived_token,
                },
            )
            long_lived_token = long_res.json().get("access_token", short_lived_token)

    except httpx.HTTPError:
        logger.exception("Network error during Instagram OAuth callback for user %s", user_id)
        return RedirectResponse(f"{settings.FRONTEND_URL}/dashboard?instagram=error")

    # 3. Check whether this Instagram account is already connected to a
    #    DIFFERENT user before saving.
    existing_res = (
        db.table("profiles")
        .select("id")
        .eq("instagram_account_id", ig_account_id)
        .neq("id", user_id)
        .limit(1)
        .execute()
    )
    if existing_res.data:
        logger.info(
            "Instagram account %s already connected to a different user (attempted by %s)",
            ig_account_id,
            user_id,
        )
        return RedirectResponse(
            f"{settings.FRONTEND_URL}/dashboard?instagram=already_connected"
        )

    # 4. Save the connection.
    #
    # NOTE: facebook_user_id is intentionally left untouched here — this
    # login flow never involves a Facebook account at all, so there's no
    # such ID to save. This means Meta's Data Deletion Callback (which
    # matches on facebook_user_id) won't find accounts connected through
    # this flow. That's a known gap to revisit before real users rely on
    # it — for now the in-app "Delete my account" button still works fine
    # regardless, since that one matches on the logged-in user directly.
    try:
        db.table("profiles").update(
            {
                "instagram_account_id": ig_account_id,
                "instagram_access_token": long_lived_token,
            }
        ).eq("id", user_id).execute()
    except Exception:
        logger.exception(
            "Failed to save Instagram connection for user %s (possible duplicate key)",
            user_id,
        )
        return RedirectResponse(
            f"{settings.FRONTEND_URL}/dashboard?instagram=already_connected"
        )

    return RedirectResponse(f"{settings.FRONTEND_URL}/dashboard?instagram=connected")


@router.delete("/disconnect", status_code=status.HTTP_200_OK)
def disconnect_instagram(
    user_id: str = Depends(verify_jwt_and_get_user_id),
    db: Client = Depends(get_supabase_admin_client),
):
    """
    Disconnects Instagram without touching campaigns or DM history.
    """
    db.table("profiles").update(
        {
            "instagram_account_id": None,
            "instagram_access_token": None,
        }
    ).eq("id", user_id).execute()

    return {"status": "disconnected"}


def send_instagram_dm(recipient_igsid: str, message_text: str, page_access_token: str) -> bool:
    """
    Sends a DM via the Instagram-native Send API (graph.instagram.com),
    using the Instagram access token saved during the OAuth callback above.
    `page_access_token` is a holdover parameter name from the old Facebook
    flow — with Instagram Login, it's really just "the Instagram account's
    own access token," but kept as-is so app/main.py doesn't need changes.
    """
    try:
        with httpx.Client(timeout=10) as client:
            res = client.post(
                f"{INSTAGRAM_GRAPH}/me/messages",
                params={"access_token": page_access_token},
                json={
                    "recipient": {"id": recipient_igsid},
                    "message": {"text": message_text},
                },
            )
        if res.status_code != 200:
            logger.error(
                "Instagram DM send failed (status %s) to %s: %s",
                res.status_code,
                recipient_igsid,
                res.text,
            )
            return False
        return True
    except httpx.HTTPError:
        logger.exception("Network error sending Instagram DM to %s", recipient_igsid)
        return False