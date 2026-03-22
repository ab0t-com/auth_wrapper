"""Health check endpoint — no authentication required.

This route is intentionally unprotected so load balancers, orchestrators
(Kubernetes liveness/readiness probes), and monitoring tools can reach it
without a token.
"""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    return {"status": "ok"}
