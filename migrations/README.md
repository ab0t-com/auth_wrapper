# migrations/

One directory per upgrade that needs attention, named `vFROM-to-vTO/`. The layout follows the
Library Migration Kit convention used by the Go SDK (`auth-sdk-go/migrations/`), so Python and Go teams follow the
same steps.

| Kit | What changes | Source-breaking? |
|---|---|---|
| [`v0.1.3-to-v0.1.4/`](v0.1.3-to-v0.1.4/) | Cache defaults aligned with the Go SDK: permission decisions 15 s / 5 s (was 30 s), API keys cached 60 s / 10 s (was uncached), unknown-`kid` JWKS refetch once per 60 s; optional `fresh=True` bypass | No (behavioural: revocation latency) |
| [`v0.1.4-to-v0.1.5/`](v0.1.4-to-v0.1.5/) | Patch: `resource_type` in the permission-cache key (security), injective tuple key, lower-case `bearer` forwarded as `Bearer`, decision-cache TTLs set in code range-checked 0–300 s | No (a TTL set in code outside 0–300 s now stops start-up, as documented) |

Each kit contains:

- **`MIGRATION.md`**: what changed, why, the before → after of every change, how to opt out, and how to roll back
  (pin back to the FROM version).
- **`migrate-check.sh`**: a read-only checker. Point it at your repo (`./migrate-check.sh /path/to/your/service`).
  It prints each place that needs a look, with the fix, and exits non-zero while ACTION findings remain, so you can
  gate CI on it. It never edits your code.
- **`CLIENT_NOTICE.md`** (when present): copy-pasteable text for teams that depend on the library.

Upgrading across several versions? Apply each kit in order and re-run your tests between them.

The kits live in this repository; they are not part of the installed package. Fetch them from the repository (or a
checkout) at the release tag you are upgrading to.
