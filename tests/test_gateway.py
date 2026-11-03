import os

import httpx
import pytest
from fastapi.testclient import TestClient

os.environ["JWT_SECRET"] = "test-secret"
os.environ["ORDERS_SERVICE_URL"] = "http://orders.test"

from app.main import app, get_client  # noqa: E402

captured = {}


def upstream_handler(request: httpx.Request) -> httpx.Response:
    captured["request"] = request
    if request.url.path == "/orders/404":
        return httpx.Response(404, json={"error": "nope"})
    if request.url.path == "/orders/boom":
        raise httpx.ConnectError("down")
    return httpx.Response(
        201, content=b'{"ok": true}', headers={"content-type": "application/json", "x-extra": "1"}
    )


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    captured.clear()
    mock = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app.dependency_overrides[get_client] = lambda: mock
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def login(client, username="alice", password="alice123"):
    return client.post("/auth/login", json={"username": username, "password": password})


def auth(client, username="alice", password="alice123"):
    token = login(client, username, password).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_login_success_and_failure(client):
    assert login(client).status_code == 200
    assert login(client, "bob", "bob123").status_code == 200
    assert login(client, "alice", "wrong").status_code == 401
    assert login(client, "nobody", "x").status_code == 401


def test_requires_token(client):
    assert client.get("/api/orders").status_code == 401
    assert client.get("/api/orders/5", headers={"Authorization": "Bearer junk"}).status_code == 401
    assert client.get("/api/other").status_code == 401


def test_unknown_api_route_404_when_authed(client):
    assert client.get("/api/other", headers=auth(client)).status_code == 404


def test_proxy_strips_prefix_and_sets_user_id(client):
    r = client.post("/api/orders/5?x=1&x=2", json={"a": 1}, headers=auth(client, "bob", "bob123"))
    req = captured["request"]
    assert req.method == "POST"
    assert str(req.url) == "http://orders.test/orders/5?x=1&x=2"
    assert req.headers["x-user-id"] == "2"
    assert "authorization" not in req.headers
    assert req.content == b'{"a":1}' or req.content == b'{"a": 1}'
    assert r.status_code == 201
    assert r.json() == {"ok": True}
    assert r.headers["x-extra"] == "1"


def test_client_cannot_spoof_user_id(client):
    headers = {**auth(client), "X-User-Id": "2"}
    client.get("/api/orders", headers=headers)
    assert captured["request"].headers["x-user-id"] == "1"


@pytest.mark.parametrize("method", ["get", "put", "patch", "delete"])
def test_all_methods_proxied(client, method):
    getattr(client, method)("/api/orders/7", headers=auth(client))
    assert captured["request"].method == method.upper()
    assert captured["request"].url.path == "/orders/7"


def test_upstream_status_passthrough(client):
    r = client.get("/api/orders/404", headers=auth(client))
    assert r.status_code == 404
    assert r.json() == {"error": "nope"}


def test_upstream_down_gives_502(client):
    assert client.get("/api/orders/boom", headers=auth(client)).status_code == 502


def test_path_traversal_rejected(client):
    r = client.get("/api/orders/../admin", headers=auth(client))
    assert r.status_code in (400, 404)
    assert "request" not in captured or captured["request"].url.path.startswith("/orders")


def test_tracing_and_locale_headers_forwarded(client):
    headers = {
        **auth(client),
        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        "tracestate": "vendor=1",
        "x-request-id": "req-123",
        "accept-language": "fr-CA",
    }
    client.get("/api/orders/1", headers=headers)
    up = captured["request"].headers
    assert up["traceparent"] == headers["traceparent"]
    assert up["tracestate"] == "vendor=1"
    assert up["x-request-id"] == "req-123"
    assert up["accept-language"] == "fr-CA"
    assert "authorization" not in up
    assert up["x-user-id"] == "1"
