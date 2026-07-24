# =============================================================================
# app/instagram_oauth.py
# -----------------------------------------------------------------------------
# The "Connect Instagram" flow. Two routes:
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
# Why a signed `state` param instead of just trusting a `user_id` query
# param: anyone could otherwise craft a callback URL with someone ELSE's
# user_id and hijack their Instagram connection. Signing `state` with our
# own secret (and checking it expires quickly) makes it unforgeable.
# =============================================================================
import time

import httpx
import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from supabase import Client

from app.auth import verify_jwt_and_get_user_id
from app.config import get_settings, get_supabase_admin_client

router = APIRouter(prefix="/api/instagram/oauth", tags=["instagram-oauth"])

FACEBOOK_OAUTH_DIALOG = "https://www.facebook.com/v20.0/dialog/oauth"
FACEBOOK_TOKEN_EXCHANGE = "https://graph.facebook.com/v20.0/oauth/access_token"
FACEBOOK_GRAPH = "https://graph.facebook.com/v20.0"

# Permissions needed to read the connected Page's Instagram account and
# eventually send/receive DMs through it.
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
