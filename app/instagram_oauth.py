# =============================================================================
# app/instagram_oauth.py
# -----------------------------------------------------------------------------
# Everything involving the Instagram Graph API lives in this file:
#
#   GET /api/instagram/oauth/start-url   (protected — needs your app's JWT)
#       Returns the Facebook OAuth dialog URL for the frontend to redirect to.
#       We can't just redirect straight from a protected route, because the
#       browser's top-level navigation to Facebook can't carry an
#       Authorization header — so instead we hand back a URL, and the
#       frontend does `window.location.href = url` itself.
#
#   GET /api/instagram/oauth/callback    (public — Facebook redirects here)
#       Facebook sends the user back here with a `code`. We exchange that
#       code for an access token, find their Instagram Business Account,
#       and save both to their profile row.
#
#   DELETE /api/instagram/oauth/disconnect  (protected)
#       Clears the stored Instagram connection without touching campaigns
#       or DM history.
#
#   send_instagram_dm(...)
#       Called from app/main.py's _match_and_record() once a trigger word
#       matches — this is what actually delivers the DM via Instagram's
#       Send API, using the Page access token saved during the callback.
#
# Why a signed `state` param instead of just trusting a `user_id` query
# param: anyone could otherwise craft a callback URL with someone ELSE's
# user_id and hijack their Instagram connection. Signing `state` with our
# own secret (and checking it expires quickly) makes it unforgeable.
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

FACEBOOK_OAUTH_DIALOG = "https://www.facebook.com/v20.0/dialog/oauth"
FACEBOOK_TOKEN_EXCHANGE = "https://graph.facebook.com/v20.0/oauth/access_token"
FACEBOOK_GRAPH = "https://graph.facebook.com/v20.0"

# Permissions needed to read the connected Page's Instagram account and
# send/receive DMs through it. Kept to exactly what's used in code —
# business_management / pages_manage_metadata were removed: neither is
# called anywhere here, and pages_manage_metadata specifically triggers
# an "Invalid Scopes" error in Development Mode without App Review.
SCOPES = "pages_show_list,instagram_basic,instagram_manage_messages"


def _make_state(user_id: str) -> str:
    settings = get_settings()
    return pyjwt.encode(
        {"user_id": user_id, "exp": int(time.time()) + 600},  # 10 min to complete login
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
        "client_id": settings.FACEBOOK_APP_ID,
        "redirect_uri": settings.INSTAGRAM_REDIRECT_URI,
        "state": state,
        "scope": SCOPES,
        "response_type": "code",
    }
    query = "&".join(f"{k}={httpx.QueryParams({k: v})[k]}" for k, v in params.items())
    return {"url": f"{FACEBOOK_OAUTH_DIALOG}?{query}"}


@router.get("/callback")
def oauth_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: Client = Depends(get_supabase_admin_client),
):
    settings = get_settings()
    user_id = _read_state(state)  # raises 400 if tampered/expired

    try:
        with httpx.Client(timeout=10) as client:
            # 1. Exchange the one-time code for a short-lived user access token.
            token_res = client.get(
                FACEBOOK_TOKEN_EXCHANGE,
                params={
                    "client_id": settings.FACEBOOK_APP_ID,
                    "client_secret": settings.FACEBOOK_APP_SECRET,
                    "redirect_uri": settings.INSTAGRAM_REDIRECT_URI,
                    "code": code,
                },
            )
            if token_res.status_code != 200:
                logger.error("Token exchange failed: %s", token_res.text)
                return RedirectResponse(f"{settings.FRONTEND_URL}/dashboard?instagram=error")
            short_lived_token = token_res.json()["access_token"]

            # 2. Exchange for a long-lived token (~60 days instead of ~1 hour).
            long_res = client.get(
                FACEBOOK_TOKEN_EXCHANGE,
                params={
                    "grant_type": "fb_exchange_token",
                    "client_id": settings.FACEBOOK_APP_ID,
                    "client_secret": settings.FACEBOOK_APP_SECRET,
                    "fb_exchange_token": short_lived_token,
                },
            )
            long_lived_token = long_res.json().get("access_token", short_lived_token)

            # 3. Find the Facebook Page this user manages, then the Instagram
            #    Business Account linked to that Page.
            pages_res = client.get(
                f"{FACEBOOK_GRAPH}/me/accounts",
                params={"access_token": long_lived_token},
            )
            pages = pages_res.json().get("data", [])
            if not pages:
                logger.info("OAuth callback: no Pages returned for user %s", user_id)
                return RedirectResponse(f"{settings.FRONTEND_URL}/dashboard?instagram=no_page")

            page = pages[0]  # simplest case: user manages one Page
            ig_res = client.get(
                f"{FACEBOOK_GRAPH}/{page['id']}",
                params={"fields": "instagram_business_account", "access_token": page["access_token"]},
            )
            ig_account = ig_res.json().get("instagram_business_account")
            if not ig_account:
                return RedirectResponse(f"{settings.FRONTEND_URL}/dashboard?instagram=not_business")

            # 4. Also grab the person's own Facebook user id (distinct from the
            #    Instagram Business Account id above) — this is the only id
            #    Meta's Data Deletion Callback gives us later, so we need it on
            #    file now to be able to match the request to this user.
            me_res = client.get(
                f"{FACEBOOK_GRAPH}/me",
                params={"access_token": long_lived_token},
            )
            facebook_user_id = me_res.json().get("id")

            # 5. Subscribe this specific Page to send webhook events to our
            #    app. Without this call, Meta never actually sends events —
            #    toggling "Subscribe" on the comments field in the App
            #    Dashboard only prepares your app to RECEIVE events IF a
            #    Page is subscribed; it doesn't subscribe any Page on its
            #    own. Wrapped in its own try so a hiccup here doesn't break
            #    the whole connect flow — worst case, comments just won't
            #    trigger until this is retried.
            try:
                sub_res = client.post(
                    f"{FACEBOOK_GRAPH}/{page['id']}/subscribed_apps",
                    params={
                        "subscribed_fields": "comments",
                        "access_token": page["access_token"],
                    },
                )
                logger.info(
                    "Page webhook subscription result: %s %s",
                    sub_res.status_code,
                    sub_res.text,
                )
            except httpx.HTTPError:
                logger.exception("Failed to subscribe Page %s to webhooks", page["id"])
    except httpx.HTTPError:
        # Network hiccup talking to Facebook — fail gracefully instead of a
        # raw 500, since this is a user-facing redirect flow.
        logger.exception("Network error during Instagram OAuth callback for user %s", user_id)
        return RedirectResponse(f"{settings.FRONTEND_URL}/dashboard?instagram=error")

    # 5. Save the connection. We store the PAGE access token (not the user
    #    token) because that's what's used to send messages as the Page's
    #    connected Instagram account.
    db.table("profiles").update(
        {
            "instagram_account_id": ig_account["id"],
            "instagram_access_token": page["access_token"],
            "facebook_user_id": facebook_user_id,
        }
    ).eq("id", user_id).execute()

    return RedirectResponse(f"{settings.FRONTEND_URL}/dashboard?instagram=connected")


@router.delete("/disconnect", status_code=status.HTTP_200_OK)
def disconnect_instagram(
    user_id: str = Depends(verify_jwt_and_get_user_id),
    db: Client = Depends(get_supabase_admin_client),
):
    """
    Disconnects Instagram without touching anything else — campaigns, DM
    history, and the account itself all stay intact. Just clears the
    three fields the OAuth callback sets, so the frontend goes back to
    showing "Connect Instagram" and the webhook handler's account lookup
    (by instagram_account_id) stops matching this user until they
    reconnect.
    """
    db.table("profiles").update(
        {
            "instagram_account_id": None,
            "instagram_access_token": None,
            "facebook_user_id": None,
        }
    ).eq("id", user_id).execute()

    return {"status": "disconnected"}


def send_instagram_dm(recipient_igsid: str, message_text: str, page_access_token: str) -> bool:
    """
    Sends an actual Instagram DM via the Send API, using the Page access
    token saved during the OAuth callback above. This is the one call
    that turns "we matched a trigger and logged it" into "the user
    actually received a message."

    recipient_igsid: the commenter's Instagram-scoped ID (IGSID) — comes
    from the real webhook payload's `value.from.id`, NOT their username.
    Returns True on success, False on any failure (never raises — a
    failed send shouldn't crash the webhook handler, since Meta expects
    a fast 200 regardless).
    """
    try:
        with httpx.Client(timeout=10) as client:
            res = client.post(
                f"{FACEBOOK_GRAPH}/me/messages",
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