"""FastAPI app: parameter annotations, dependency injection, async handlers.

Exercises DSL types unique to FastAPI/Litestar:
  - InputParameterPattern (Query, Body, Header, Cookie, Path defaults)
  - DependencyPattern (Depends, Security)
  - RouteDecorator (same as Flask but async)
"""

from fastapi import (
    Body,
    Cookie,
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    Path,
    Query,
    Security,
    UploadFile,
)
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer

from .auth import get_current_user, oauth2_scheme, require_admin
from .deps import get_db, get_settings

app = FastAPI()


# -- EP-1: Routes (RouteDecorator — async) -------------------------------


@app.get("/")
async def index():
    """Async GET route."""
    return {"message": "hello"}


@app.post("/items")
async def create_item():
    """Async POST route."""
    return {"created": True}


@app.get("/items/{item_id}")
async def get_item(item_id: int):
    """Route with path parameter (no explicit Path() default)."""
    return {"item_id": item_id}


@app.get("/explicit_items/{item_id}")
async def get_explicit_item(item_id: int = Path(..., ge=1)):
    """Route with explicit Path() parameter marker."""
    return {"item_id": item_id}


# -- EP-2: Input parameter annotations (InputParameterPattern) ----------


@app.get("/search")
async def search(
    q: str = Query(None, description="Search query"),
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0),
):
    """Query parameters via parameter annotations.

    Each parameter with Query() default → detected as Query input source.
    """
    return {"q": q, "limit": limit, "offset": offset}


@app.get("/with_header")
async def with_header(
    x_token: str = Header(...),
    x_api_key: str | None = Header(None),
):
    """Header inputs via parameter annotations.

    Header() default → detected as Header input source.
    """
    return {"token": x_token, "api_key": x_api_key}


@app.get("/with_cookie")
async def with_cookie(
    session_id: str | None = Cookie(None),
):
    """Cookie input via parameter annotation.

    Cookie() default → detected as Cookie input source.
    """
    return {"session_id": session_id}


@app.post("/body")
async def create_from_body(
    name: str = Body(...),
    quantity: int = Body(1),
):
    """JSON body inputs via Body() parameter markers."""
    return {"name": name, "quantity": quantity}


@app.post("/form")
async def submit_form(
    username: str = Form(...),
    csrf_token: str = Form(...),
):
    """Form inputs via Form() parameter markers."""
    return {"username": username, "csrf": csrf_token}


@app.post("/upload")
async def upload_avatar(
    avatar: UploadFile = File(...),
):
    """File upload via File() parameter marker."""
    return {"filename": avatar.filename}


# -- Dependency Injection (DependencyPattern) ----------------------------


@app.get("/db_item/{item_id}")
async def get_db_item(item_id: int, db=Depends(get_db)):
    """Depends(get_db) — lifecycle_and_input dependency.

    The engine must:
    1. Detect Depends(get_db) as a DependencyPattern match
    2. Resolve get_db as the dependency callable
    3. Treat its return value as an injected input to the handler
    4. Include get_db's body in the route's reachable scope
    """
    result = db.execute("SELECT * FROM items WHERE id = ?", (item_id,))
    return {"item": result}


@app.get("/protected")
async def protected(user=Depends(get_current_user)):
    """Depends(get_current_user) — guard dependency.

    get_current_user raises HTTPException(401) if not authenticated.
    The engine must detect this as a security check on the route.
    """
    return {"user": user}


@app.get("/admin")
async def admin_panel(admin=Depends(require_admin)):
    """Nested guard dependency: require_admin → get_current_user → oauth2_scheme."""
    return {"admin": admin}


@app.get("/with_settings")
async def with_settings(settings=Depends(get_settings)):
    """Nested dependency chain: get_settings depends on get_db."""
    return {"debug": settings.get("debug")}


# -- Security schemes (SecurityCheckPattern via DI) ----------------------


@app.get("/oauth2_protected")
async def oauth2_protected(token: str = Security(oauth2_scheme)):
    """Security(oauth2_scheme) — security dependency.

    OAuth2PasswordBearer is declared as a SecurityCheckPattern.
    Security() is a special Depends() for auth schemes.
    """
    return {"token": token}


# -- Effects -------------------------------------------------------------


@app.get("/redirect")
async def do_redirect():
    """RedirectResponse → RESPONSE_WRITE effect."""
    return RedirectResponse(url="/")


@app.get("/json")
async def json_resp():
    """JSONResponse → RESPONSE_WRITE effect."""
    return JSONResponse(content={"ok": True})
