# Next Steps After Scaffolding

The template is a complete, runnable service. These are the steps to take it to production.

## Register With Auth Service

Copy the registration script from the auth_fastapi_skill:
```bash
cp path/to/auth_fastapi_skill/scripts/register-service-permissions.sh ./scripts/
./scripts/register-service-permissions.sh
```

Or see the [auth_fastapi_skill registration reference](../../auth_fastapi_skill/references/registration.md) for details.

## Add Middleware (Optional)

For blanket auth on all routes except health/docs:

```python
from ab0t_auth.middleware import AuthMiddleware

app.add_middleware(
    AuthMiddleware,
    guard=auth,
    exclude_paths=["/health", "/docs", "/openapi.json", "/projects/public"],
)
```

## Swap Database Backend

The Repository in `db.py` uses SQLite. To swap:

1. Install your driver (`sqlalchemy`, `motor`, `boto3`, etc.)
2. Reimplement the Repository class with the same method signatures
3. Keep models compatible — auth checks rely on `.user_id` and `.org_id`
4. Keep `_apply_filters()` compatible with `get_user_filter()` output

**Example for SQLAlchemy/Postgres:**
```python
class Repository:
    def __init__(self, database_url: str):
        self.engine = create_async_engine(database_url)
        self.session = async_sessionmaker(self.engine)

    async def list_projects(self, filters: dict) -> list[Project]:
        async with self.session() as session:
            query = select(ProjectModel)
            for key, value in filters.items():
                query = query.where(getattr(ProjectModel, key) == value)
            result = await session.execute(query)
            return [self._to_project(row) for row in result.scalars()]
```

## Testing with Auth Bypass

For local development and tests:

```bash
AB0T_AUTH_DEBUG=true AB0T_AUTH_BYPASS=true uvicorn app.main:app --reload
```

Both env vars must be `"true"`. Bypass creates a synthetic user with configurable permissions:

```bash
AB0T_AUTH_BYPASS_PERMISSIONS=pm.read.projects,pm.create.projects,pm.write.projects,pm.read.tasks,pm.create.tasks
AB0T_AUTH_BYPASS_ROLES=pm-contributor
```

## Production Checklist

- [ ] `AB0T_AUTH_DEBUG=false` and `AB0T_AUTH_BYPASS=false`
- [ ] `AB0T_AUTH_PERMISSION_CHECK_MODE=server` for instant revocation
- [ ] `AB0T_AUTH_AUDIENCE` set to your service slug
- [ ] `.permissions.json` registered via registration script
- [ ] `credentials/` in `.gitignore`
- [ ] Phase 2 on every route with a resource ID path param
- [ ] `get_user_filter()` on every list/search query
- [ ] `cross_tenant` NOT implied by `admin`
- [ ] SQLite replaced with production database
- [ ] `data.db` NOT in version control
