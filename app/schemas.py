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

    trigger_word: str = Field(..., min_length=1, max_length=100)
    destination_link: HttpUrl
    message_template: str | None = Field(default=None, max_length=1000)

    class Config:
        json_schema_extra = {
            "example": {
                "trigger_word": "PRICE",
                "destination_link": "https://yourshop.com/pricing",
                "message_template": "Hey! Here's our pricing page 👇",
            }
        }


class CampaignUpdate(BaseModel):
    """
    Shape of the JSON body expected on PATCH /api/campaigns/{id}. Every
    field is optional — the frontend sends only what actually changed,
    and the endpoint only updates keys that were provided.
    """

    trigger_word: str | None = Field(default=None, min_length=1, max_length=100)
    destination_link: HttpUrl | None = None
    message_template: str | None = Field(default=None, max_length=1000)
    is_active: bool | None = None


class CampaignOut(BaseModel):
    """Shape of a campaign object as returned to the client."""

    id: UUID
    trigger_word: str
    destination_link: str
    message_template: str | None = None
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
    recipient_account_id: str = Field(..., min_length=1)
    commenter_igsid: str | None = None


class WebhookResult(BaseModel):
    status: str
    matched_trigger: str | None = None
    dm_sent_to: str | None = None
    dms_sent_count: int | None = None
    dm_delivery: str | None = None


class ActivityEvent(BaseModel):
    id: UUID
    trigger_word: str
    commenter_username: str
    sent_at: datetime


class DailyTrendPoint(BaseModel):
    date: str
    count: int


class AnalyticsOut(BaseModel):
    dms_sent_count: int
    free_tier_limit: int
    daily_trend: list[DailyTrendPoint]
    recent_activity: list[ActivityEvent]