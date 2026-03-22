"""Application entrypoint.

The lifespan context manager ensures JWKS keys are fetched at startup
and the HTTP client is cleaned up on shutdown. Without it, the first
request would block while keys are fetched.

register_auth_exception_handlers() converts auth errors into proper
JSON responses (401 for bad tokens, 403 for missing permissions)
instead of generic 500s.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .auth import auth, register_auth_exception_handlers
from .config import settings
from .api import health, items


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with auth.lifespan():  # Fetches JWKS keys, sets up caches
        yield


app = FastAPI(title=settings.SERVICE_NAME, lifespan=lifespan)
register_auth_exception_handlers(app)  # Converts auth errors to 401/403 JSON

app.include_router(health.router)
app.include_router(items.router, prefix="/items", tags=["items"])
