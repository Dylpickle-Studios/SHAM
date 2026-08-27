# API compatibility

`/api/v1` is SHAM's supported public automation API. New integrations should
use it. Version 1 returns errors in a stable structured form:

```json
{ "error": { "code": "NOT_FOUND", "message": "Site not found" } }
```

The existing `/api/...` endpoints are compatibility aliases and retain their
current response shapes. They will remain available for the current major
release line and are deprecated only with a documented migration path in the
release notes. SHAM will not remove or change a `/api/v1` endpoint
incompatibly within a v1-supported release line; additive fields and endpoints
may be introduced at any time.

The machine-readable contract is [openapi.json](openapi.json).
