# Architecture

`tinywasm/rbac` owns role, permission, assignment, and authorization decision
mechanics. Assignments are keyed by `user.SubjectID`; this module does not know
how subjects authenticate or how sessions are transported.

Applications declare policy by creating roles and grants, then inject
`rbac.Service.Can` into their router. `rbac` never imports `tinywasm/auth`;
`auth` never imports `rbac`. Both depend only on `tinywasm/user`.

## Dependency Direction

```mermaid
flowchart TD
    U[github.com/tinywasm/user<br/>SubjectID + Subject] --> R[github.com/tinywasm/rbac]
    U --> A[github.com/tinywasm/auth<br/>never imports rbac]
    R --> C[application composition root]
    A --> C
    R -.->|never| A
    A -.->|never| R
```

Rules:

- `user` imports neither sibling.
- `rbac` imports `user` and may depend on `orm`, `ddl`, `model`, `input`.
  It never imports `auth` or a concrete provider.
- Only the composition root imports both `auth` and `rbac`.

## Concepts

- **Roles** have an ID, code, name, description.
- **Permissions** have an ID, resource, and action string (`crud` letters).
- **Assignments** via `UserRole` and `RolePermission` are keyed by
  `SubjectID` string (`user_id` column) and role/permission IDs.
- **Policy belongs to the consumer**: `Register` builds permissions from the
  app's `RBACObject` handlers; no role or resource constants live here.

```mermaid
flowchart TD
    A[Application policy<br/>CreateRole / CreatePermission] --> B[rbac.Service]
    B --> C[Role and permission store]
    D[user.SubjectID] --> B
    B --> E[Authorization decision<br/>Can / HasPermission]
```

Cache invalidation is encapsulated in the service: mutations delete or
invalidate the per-subject cache. Empty or unknown `SubjectID` is denied; a
malformed stored `action` denies and surfaces `EventPermissionCorrupt`.
