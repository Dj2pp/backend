import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.config import get_settings

bearer_scheme = HTTPBearer()
_settings = get_settings()

def verify_jwt_and_get_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> str:
    """
    Verifies the symmetric HS256 JWT using the Legacy JWT Secret string.
    """
    token = credentials.credentials

    try:
        # Decode directly using the string secret key from your dashboard env
        payload = jwt.decode(
            token,
            _settings.SUPABASE_JWT_SECRET,   # <-- Pass the string secret variable here
            algorithms=["HS256"],            # <-- Locked to HS256
            audience="authenticated",       
            options={"require": ["exp", "sub", "aud"]}, # Drop 'iss' check if you see mismatch errors
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MY_CUSTOM_ERROR: Token signature has expired.",
        )
    except jwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MY_CUSTOM_ERROR: Audience mismatch! Expected: authenticated",
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"MY_CUSTOM_ERROR: General invalid token error: {str(e)}",
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MY_CUSTOM_ERROR: Token parsed, but 'sub' claim is completely missing.",
        )

    return user_id