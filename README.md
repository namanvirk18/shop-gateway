# Shop Gateway

FastAPI gateway for a small online shop. It authenticates users with JWTs and proxies
`/api/orders` and `/api/orders/*` to the orders service.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Run (port 8000)

```bash
export JWT_SECRET="change-me-to-a-long-random-string"
export ORDERS_SERVICE_URL="http://localhost:9000"
# optional: DB_PATH (default ./gateway.db)
python -m app.main
# or: uvicorn app.main:app --port 8000
```

Both `JWT_SECRET` and `ORDERS_SERVICE_URL` are required; the app refuses to start without them.

On first start the SQLite `users` table is seeded with `alice` (id 1, `alice123`) and
`bob` (id 2, `bob123`). Passwords are stored as salted PBKDF2-SHA256 hashes.

## Usage

```bash
TOKEN=$(curl -s localhost:8000/auth/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"alice123"}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl localhost:8000/api/orders/5 -H "Authorization: Bearer $TOKEN"
```

- Every `/api/*` route needs `Authorization: Bearer <jwt>` (tokens last 1 hour).
- `/api/orders[/...]` (any method) is forwarded to `$ORDERS_SERVICE_URL/orders[/...]` with the
  user's id in `X-User-Id`. Any `X-User-Id` or `Authorization` header sent by the client is not
  forwarded. The upstream status code and body are returned unchanged; if the orders service is
  unreachable the gateway returns 502.
- Other `/api/*` paths return 404 (after authentication).

## Tests

```bash
pytest
```

The orders service is mocked with `httpx.MockTransport`; no network is needed.
