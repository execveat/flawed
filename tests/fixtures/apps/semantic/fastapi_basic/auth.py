"""FastAPI security dependencies for check resolution tests."""

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Security dependency that validates a Bearer token.

    Raises HTTPException(401) if invalid → acts as a guard.
    The engine must detect this as a security check on any route
    that depends on get_current_user.
    """
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"id": 1, "name": "testuser"}


async def require_admin(user=Depends(get_current_user)):
    """Nested security dependency: requires admin role.

    DI chain: handler → require_admin → get_current_user → oauth2_scheme
    All three are security-relevant.
    """
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return user
