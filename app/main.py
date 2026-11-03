import os
import time
from contextlib import asynccontextmanager

import httpx
import jwt
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from . import db

JWT_ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 3600

# Hop-by-hop / identity headers that must not be forwarded upstream.
_DROP_REQUEST_HEADERS = {
    "host", "authorization", "x-user-id", "content-length", "connection",
    "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
    "proxy-authorization", "proxy-authenticate",
}
_DROP_RESPONSE_HEADERS = {
    "content-length", "content-encoding", "transfer-encoding", "connection",
    "keep-alive", "te", "trailer", "upgrade",
}


def jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET environment variable is required")
    return secret


def orders_url() -> str:
    url = os.environ.get("ORDERS_SERVICE_URL")
    if not url:
        raise RuntimeError("ORDERS_SERVICE_URL environment variable is required")
    return url.rstrip("/")


@asynccontextmanager
async def lifespan(app: FastAPI):
    jwt_secret()
    orders_url()
    db.init_db()
    app.state.client = httpx.AsyncClient(timeout=30.0)
    yield
    await app.state.client.aclose()


app = FastAPI(title="Shop Gateway", lifespan=lifespan)


def get_client(request: Request) -> httpx.AsyncClient:
    return request.app.state.client


bearer = HTTPBearer(auto_error=False)


def current_user_id(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> int:
    unauthorized = HTTPException(
        status_code=401,
        detail="Invalid or missing token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if creds is None:
        raise unauthorized
    try:
        payload = jwt.decode(
            creds.credentials,
            jwt_secret(),
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
        return int(payload["sub"])
    except (jwt.PyJWTError, ValueError):
        raise unauthorized


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/auth/login")
def login(body: LoginRequest):
    user = db.get_user_by_username(body.username)
    if user is None:
        # Burn comparable time so unknown users aren't distinguishable by timing.
        db.verify_password(body.password, db.hash_password("x"))
        ok = False
    else:
        ok = db.verify_password(body.password, user["password_hash"])
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    now = int(time.time())
    token = jwt.encode(
        {"sub": str(user["id"]), "iat": now, "exp": now + TOKEN_TTL_SECONDS},
        jwt_secret(),
        algorithm=JWT_ALGORITHM,
    )
    return {"access_token": token, "token_type": "bearer"}


api = APIRouter(prefix="/api", dependencies=[Depends(current_user_id)])

PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


async def forward(
    request: Request,
    client: httpx.AsyncClient,
    base_url: str,
    user_id: int,
) -> Response:
    """Forward an /api/* request to an upstream service and relay its response.

    Strips the "/api" prefix, passes incoming headers through (tracing, locale,
    etc.) except hop-by-hop and identity headers, and sets X-User-Id from the
    authenticated user.
    """
    # /api/orders/5 -> /orders/5
    path = request.url.path[len("/api"):]
    if ".." in path.split("/"):
        raise HTTPException(status_code=400, detail="Invalid path")

    headers = {
        k: v for k, v in request.headers.items() if k.lower() not in _DROP_REQUEST_HEADERS
    }
    headers["X-User-Id"] = str(user_id)

    try:
        upstream = await client.request(
            request.method,
            base_url + path,
            params=request.query_params.multi_items(),
            headers=headers,
            content=await request.body(),
        )
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Orders service unavailable")

    response_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in _DROP_RESPONSE_HEADERS
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=response_headers,
    )


@api.api_route("/orders", methods=PROXY_METHODS)
@api.api_route("/orders/{path:path}", methods=PROXY_METHODS)
async def proxy_orders(
    request: Request,
    user_id: int = Depends(current_user_id),
    client: httpx.AsyncClient = Depends(get_client),
):
    return await forward(request, client, orders_url(), user_id)


@api.api_route("/{path:path}", methods=PROXY_METHODS)
async def api_not_found(path: str):
    raise HTTPException(status_code=404, detail="Not found")


app.include_router(api)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
