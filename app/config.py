# =============================================================================
# app/config.py
# -----------------------------------------------------------------------------
# Centralizes all environment configuration and the Supabase client.
# Everything here is loaded ONCE at startup, not re-read on every request.
# =============================================================================
import os
from functools import lru_cache

from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()  # reads variables from a local .env file into os.environ


class Settings:
    """
    Plain settings object. In a bigger project you'd use pydantic-settings
    for automatic validation, but for learning purposes explicit os.getenv
    calls make it 100% clear where every value comes from.
    """

    # Your Supabase project URL, e.g. https://xxxxx.supabase.co
    SUPABASE_URL: str = os.environ["SUPABASE_URL"]

    # The SERVICE ROLE key. This key BYPASSES Row Level Security, so it
    # must NEVER be sent to the frontend or committed to git. It lives only
    # in this backend's environment. We use it here because our own JWT
    # verification (see app/auth.py) is what enforces "who can see what" —
    # the service key just lets our already-trusted backend talk to the DB.
    SUPABASE_SERVICE_ROLE_KEY: str = os.environ["SUPABASE_SERVICE_ROLE_KEY"]

    # Used to verify JWTs issued by Supabase Auth for incoming requests.
    # Supabase exposes a JWKS (JSON Web Key Set) endpoint per project that
    # we fetch public keys from — see app/auth.py for why this is safer
    # than a shared secret.
    SUPABASE_JWKS_URL: str = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"

    # Supabase Auth sets this as the "issuer" (`iss`) claim on every JWT it
    # mints. We check it during verification so a token from some *other*
    # Supabase project (or a forged one) can't be replayed against us.
    SUPABASE_JWT_ISSUER: str = f"{SUPABASE_URL}/auth/v1"
    SUPABASE_JWT_SECRET: str = os.environ["SUPABASE_JWT_SECRET"]
    # Free tier ceiling — pulled out as a constant, not a magic number
    # buried in route logic, so it's obvious where to change it later
    # (e.g. when you add a paid tier with a higher/no limit).
    FREE_TIER_DM_LIMIT: int = 100
    WEBHOOK_SECRET: str = os.environ["WEBHOOK_SECRET"]

    # Instagram DMs are sent via the Instagram Graph API, which is reached
    # through a Facebook Login for Business OAuth flow (Instagram's own
    # login isn't enough by itself — the account has to be a Business or
    # Creator account linked to a Facebook Page).
    FACEBOOK_APP_ID: str = os.environ["FACEBOOK_APP_ID"]
    FACEBOOK_APP_SECRET: str = os.environ["FACEBOOK_APP_SECRET"]
    # Must exactly match a "Valid OAuth Redirect URI" configured in your
    # Facebook App dashboard, e.g. https://your-api.com/api/instagram/oauth/callback
    INSTAGRAM_REDIRECT_URI: str = os.environ["INSTAGRAM_REDIRECT_URI"]
    # Used only to sign the short-lived `state` param (CSRF protection for
    # the OAuth redirect) — separate from the Supabase JWT verification.
    OAUTH_STATE_SECRET: str = os.environ["OAUTH_STATE_SECRET"]
    FRONTEND_URL: str = os.environ.get("FRONTEND_URL", "https://dm-coral-chi.vercel.app")

@lru_cache
def get_settings() -> Settings:
   
    # lru_cache means this object is constructed exactly once per process
    # and reused — avoids re-reading env vars on every request.
    return Settings()


@lru_cache
def get_supabase_admin_client() -> Client:
    """
    A single, reused Supabase client authenticated with the service role
    key. This is our direct line to Postgres for all backend DB operations.
    """
    settings = get_settings()
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)
