# =============================================================================
# app/schemas.py
# -----------------------------------------------------------------------------
# Pydantic models define the SHAPE of data going in and out of the API.
# FastAPI uses these to: validate incoming JSON automatically (rejecting
# malformed requests with a 422 before your route code even runs), and to
# serialize outgoing responses consistently.
# =============================================================================
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl


class CampaignCreate(BaseModel):
    """Shape of the JSON body expected on POST /api/campaigns."""

    # min_length prevents someone submitting an empty trigger word that
    # would match on every comment.
    trigger_word: str = Field(..., min_length=1, max_length=100)

    # HttpUrl gives us free validation that this is actually a well-formed
    # URL (must have a scheme like https://) before it ever touches the DB.
    destination_link: HttpUrl

    class Config:
        json_schema_extra = {
            "example": {
                "trigger_word": "PRICE",
                "destination_link": "https://yourshop.com/pricing",
            }
        }


class CampaignOut(BaseModel):
    """Shape of a campaign object as returned to the client."""

    id: UUID
    trigger_word: str
    destination_link: str
    is_active: bool
    created_at: datetime


class InstagramWebhookPayload(BaseModel):
    """
    Simulates the payload Instagram's real webhook would send when someone
    comments on a post. A real integration would verify Meta's signature
    header here too (X-Hub-Signature-256) — omitted since this endpoint is
    explicitly a simulation per the assignment, but noted in the README.
    """

    commenter_username: str = Field(..., min_length=1)
    comment_text: str = Field(..., min_length=1)
    # In a real Instagram payload this would be the Instagram Business
    # Account ID tied to the post. We use it to figure out WHICH of your
    # users this comment belongs to.
    recipient_account_id: str = Field(..., min_length=1)


class WebhookResult(BaseModel):
    status: str
    matched_trigger: str | None = None
    dm_sent_to: str | None = None
    dms_sent_count: int | None = None


class DailyTrendPoint(BaseModel):
    """One day's worth of send volume, used to draw the dashboard chart."""

    date: str  # ISO date, e.g. "2026-07-10"
    count: int


class ActivityEvent(BaseModel):
    """A single logged DM send, used for the dashboard's live activity feed."""

    id: UUID
    commenter_username: str
    trigger_word: str
    sent_at: datetime


class AnalyticsOut(BaseModel):
    dms_sent_count: int
    free_tier_limit: int
    daily_trend: list[DailyTrendPoint]
    recent_activity: list[ActivityEvent]
