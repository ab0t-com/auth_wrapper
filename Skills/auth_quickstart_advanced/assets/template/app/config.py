"""Service configuration via environment variables.

All AB0T_AUTH_* settings can be overridden in .env or the environment.
See .env.example for the full list.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Service identity
    SERVICE_NAME: str = "Project Manager"

    # Auth service connection — where JWT validation and permission checks happen
    AB0T_AUTH_URL: str = "https://auth.service.ab0t.com"

    # Audience — must match what's registered in .permissions.json.
    # Prevents tokens issued for other services from being accepted here.
    AB0T_AUTH_AUDIENCE: str = "pm"

    # Debug mode — enables verbose auth logging. Never true in production.
    AB0T_AUTH_DEBUG: bool = False

    # Bypass mode — skips all auth checks with a synthetic user.
    # Requires BOTH debug=true AND bypass=true (defense-in-depth).
    AB0T_AUTH_BYPASS: bool = False

    # Permission check mode:
    #   "client" = check permissions from JWT claims (instant, but stale until token expires)
    #   "server" = check permissions via API call (5-10ms, but revocations take effect immediately)
    # Use "server" in production for instant revocation support.
    AB0T_AUTH_PERMISSION_CHECK_MODE: str = "server"

    # Database path — SQLite file. Swap Repository implementation in db.py for other backends.
    DB_PATH: str = "data.db"

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
