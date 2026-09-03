---
PLAN: "fix(security): unique role code per project, revoke-by-code contract, cache invalidation"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 2716331072071053921
---

> Este plan se despacha con el flujo CodeJob. Ver skill: `agents-workflow`.
> No ejecutes `gopush` ni `codejob` — son herramientas del desarrollador local.

# PLAN — `tinywasm/rbac`: que revocar revoque

## Contexto

Auditoría de seguridad de `veltylabs/iam` (2026-09-02). `iam` es el servicio
central de RBAC de todos los proyectos Velty y monta este paquete. Los dos
hallazgos de abajo hacen que **quitarle un rol a alguien pueda no quitárselo**.

Doctrina obligatoria: [CONSTRUCTION_HARNESS.md](https://github.com/tinywasm/app-releases/blob/main/docs/CONSTRUCTION_HARNESS.md).
Los principios que gobiernan este plan:

- **3 · Estados ilegales no representables.** Dos roles con el mismo `code` en
  el mismo proyecto es un estado ilegal que hoy se puede escribir.
- **6 · Nunca fallo silencioso.** `DeleteRole` devuelve `nil` cuando no borró nada.
- **"A missing contract at a boundary is a defect in the library."** `iam` tuvo
  que hacer `db.Delete(&rbac.UserRole{}, …)` a mano porque falta el contrato.

---

## Hallazgo R-1 (Alto) · `role.code` no es único por proyecto

`models.go`, `RoleModel`: la clave primaria es `(project_id, id)`. `code` es
una columna común, sin restricción de unicidad. Pero `GetRoleByCode` resuelve
así:

```go
func (m *Service) GetRoleByCode(projectID string, code model.RoleCode) (*Role, error) {
	qb := m.db.Query(&Role{}).Where(Role_.ProjectId).Eq(projectID).Where(Role_.Code).Eq(string(code))
	roles, err := ReadAllRole(qb)
	...
	return roles[0], nil     // <- la primera, en silencio
}
```

En `veltylabs/iam` hay **dos** caminos que crean roles con ids distintos:

- el panel de administración: `rbacSvc.CreateRole(projectID, ids.NewID(), code, …)`
- `POST /api/roles/assign`: `rbacSvc.CreateRole(projectID, roleCode, model.RoleCode(roleCode), …)`
  — usa el propio `code` como `id`.

Los dos pueden crear el mismo `code` con `id` distinto. A partir de ahí:

- `GetRoleByCode` devuelve uno de los dos, arbitrariamente.
- Borrar el rol desde el panel borra **ese** y sus `UserRole`, pero deja vivo
  el otro con todos sus usuarios asignados.
- El administrador ve el rol desaparecer de la lista y cree haber revocado el
  acceso. No lo revocó.

## Hallazgo R-2 (Medio) · Falta el contrato de revocación por `code`

`Service` expone `RevokeRole(projectID, userID, roleID)` — por `id`. Un
consumidor que trabaja con `code` (el vocabulario que `iam` publica hacia
afuera) tiene que resolver el `id` primero. Y no hay forma de listar los
usuarios de un rol.

Resultado medible en `veltylabs/iam/modules/admin/handler.go`:

```go
if err := db.Delete(&rbac.UserRole{},
	storage.Eq(rbac.UserRole_.ProjectId, req.ProjectId),
	storage.Eq(rbac.UserRole_.UserId, u.Id),
	storage.Eq(rbac.UserRole_.RoleId, role.Id)); err != nil {
```

El consumidor se saltea `Service.RevokeRole` y borra la fila a mano — **y por
lo tanto no invalida `ucache`**. Los permisos revocados siguen concediéndose
desde el caché hasta que el desalojo FIFO llegue a esa entrada. Eso no es un
defecto de `iam`: es la firma de que falta el contrato acá.

## Hallazgo R-3 (Bajo) · `DeleteRole` no distingue "borrado" de "no existía"

```go
if len(roles) == 0 {
	return nil // Or ErrNotFound
}
```

El propio comentario delata la duda. Un llamador que quiere responder 404 no
puede.

---

## Etapa 1 · `code` único por proyecto (R-1)

### 1.1 · Restricción en el modelo

`models.go`, `RoleModel`, campo `code`:

```go
{Name: "code", Type: model.Text(), NotNull: true},
```

La unicidad es **compuesta** `(project_id, code)`, no de columna: dos
proyectos distintos pueden y deben tener un rol `admin` cada uno. Verificá qué
soporta `tinywasm/model`/`tinywasm/ddl` para índices únicos compuestos:

- **Si lo soporta** declaralo ahí y dejá que `Migrate` lo aplique.
- **Si no lo soporta**, no inventes un mecanismo local (doctrina §"Lego
  pieces"): emitilo desde `migrate.go` como una sentencia explícita después
  del `Sync`, con este comentario:

```go
// Índice único compuesto: dos roles con el mismo code dentro de un proyecto
// hacen que GetRoleByCode devuelva uno arbitrario y que borrar el rol deje
// vivo al otro con sus usuarios asignados — una revocación que no revoca.
// Se emite acá y no en el modelo porque tinywasm/ddl todavía no expresa
// unicidad compuesta; si algún día lo hace, esto se muda al modelo.
const roleCodeUniqueIndex = `CREATE UNIQUE INDEX IF NOT EXISTS ` +
	`idx_role_project_code ON role (project_id, code)`
```

y ejecutalo dentro de `Migrate` tras sincronizar `Role`.

**Migración de datos existentes:** antes de crear el índice, `Migrate` debe
detectar duplicados y **fallar ruidosamente** en vez de crear el índice a
ciegas (el `CREATE UNIQUE INDEX` fallaría igual, pero con un error de SQLite
ilegible). Función nueva, exportada:

```go
// ErrDuplicateRoleCode reporta que la base tiene dos roles con el mismo code
// dentro de un proyecto — un estado que este paquete ya no permite crear pero
// que una base anterior a esta versión pudo haber acumulado. Se resuelve a
// mano: hay que decidir cuál de los dos roles sobrevive y reasignar sus
// usuarios. Migrate NO lo resuelve solo porque elegir cuál borrar es una
// decisión de política, no de esquema.
var ErrDuplicateRoleCode = fmt.Err("rbac", "duplicate", "role", "code")

// FindDuplicateRoleCodes devuelve los pares (project_id, code) que aparecen
// más de una vez. Vacío = la base está lista para el índice único.
func FindDuplicateRoleCodes(db *orm.DB) ([]RoleCodeRef, error)

// RoleCodeRef nombra un rol por su par natural, el que el consumidor usa.
type RoleCodeRef struct {
	ProjectID string
	Code      string
}
```

Mensaje exacto: `rbac duplicate role code`.

### 1.2 · `CreateRole` rechaza el duplicado

`rbac.go`. Hoy `CreateRole` trata la violación de unicidad como "actualizá la
fila existente" buscando por `(project_id, id)`. Con el índice nuevo hay dos
violaciones posibles y hay que distinguirlas:

- Choque por `(project_id, id)` → sigue siendo el upsert de hoy (mismo rol,
  se actualizan `code`/`name`/`description`).
- Choque por `(project_id, code)` con **otro** `id` → `ErrDuplicateRoleCode`.
  Nunca lo silencies: crear un segundo rol con un `code` ya tomado es el
  defecto que este plan cierra.

Implementalo comprobando primero con `GetRoleByCode`: si existe un rol con ese
`code` y su `Id` **no** es el que se está creando → `ErrDuplicateRoleCode`
antes de tocar la base.

### 1.3 · `GetRoleByCode` deja de elegir en silencio

```go
if len(roles) > 1 {
	return nil, ErrDuplicateRoleCode
}
```

Con el índice único esto no debería pasar nunca; que devuelva un error en vez
de `roles[0]` es lo que hace que, si pasa, se sepa (principio 6).

## Etapa 2 · Contrato de revocación por `code` (R-2)

`rbac.go`, métodos nuevos en `Service`. Todos invalidan `ucache`.

```go
// RevokeRoleByCode quita el rol identificado por su code al usuario dentro
// del proyecto. Es el par de AssignRoleByCode y el camino que debe usar un
// consumidor que habla en codes — nunca borrar la fila UserRole a mano: el
// borrado directo NO invalida el caché de permisos y deja concediendo
// accesos ya revocados.
//
// Idempotente: revocar un rol que el usuario no tiene no es un error.
// ErrRoleNotFound si el code no existe en el proyecto.
func (m *Service) RevokeRoleByCode(projectID, userID string, code model.RoleCode) error

// AssignRoleByCode concede el rol identificado por su code. Idempotente.
// ErrRoleNotFound si el code no existe en el proyecto — a diferencia de
// CreateRole, NO lo crea: conceder un rol y definirlo son decisiones
// distintas y mezclarlas hace que un typo en el code cree un rol vacío.
func (m *Service) AssignRoleByCode(projectID, userID string, code model.RoleCode) error

// UsersInRole devuelve los ids de usuario que tienen el rol. Sólo ids: este
// paquete no conoce la tabla de usuarios (ver ARCHITECTURE.md), así que
// resolver perfiles es del consumidor.
func (m *Service) UsersInRole(projectID string, code model.RoleCode) ([]string, error)

// RoleUserCount devuelve cuántos usuarios tienen el rol, sin traerlos.
func (m *Service) RoleUserCount(projectID string, code model.RoleCode) (int64, error)
```

Error nuevo en `errors.go`:

```go
// ErrRoleNotFound: el code no existe en ese proyecto. Distinto de "el
// usuario no tenía el rol", que no es un error.
var ErrRoleNotFound = fmt.Err("rbac", "role", "not", "found")
```

Mensaje exacto: `rbac role not found`.

`RevokeRole` (por `id`) se conserva; `RevokeRoleByCode` lo llama tras resolver
el `code`. Una sola implementación del borrado y de la invalidación de caché
(principio 4).

## Etapa 3 · `DeleteRole` deja de mentir (R-3)

`rbac.go`:

```go
if len(roles) == 0 {
	return ErrRoleNotFound
}
```

Y borrá el comentario `// Or ErrNotFound`.

Método nuevo, para el consumidor que trabaja por `code`:

```go
// DeleteRoleByCode borra el rol y todas sus asignaciones. ErrRoleNotFound si
// el code no existe en el proyecto.
func (m *Service) DeleteRoleByCode(projectID string, code model.RoleCode) error
```

**Anti-footgun:** `DeleteRole` ya borra `UserRole` y `RolePermission` a mano
porque `tinywasm/orm` no cascadea. Eso es correcto y deliberado — no lo
"simplifiques" confiando en un `ON DELETE CASCADE` que no existe.

## Etapa 4 · Tests

Todos bajo `tests/`, consumiendo el paquete real. Base en memoria:
`orm.New(mem.New())` + `rbac.Migrate(db.RawConn(), sqlt.NewCompiler())`, como
ya hacen los tests del repo.

| Test | Fija |
|---|---|
| `TestCreateRoleRejectsDuplicateCode` | R-1: mismo `(project, code)` con otro `id` → `ErrDuplicateRoleCode` |
| `TestSameCodeAllowedInDifferentProjects` | R-1: la unicidad es compuesta, no de columna |
| `TestCreateRoleSameIDStillUpserts` | R-1: el upsert por `(project_id, id)` de siempre sigue andando |
| `TestGetRoleByCodeErrorsOnAmbiguity` | R-1: sembrando el duplicado directo por `db.Create`, `GetRoleByCode` devuelve error y no `roles[0]` |
| `TestMigrateDetectsPreexistingDuplicates` | R-1: base con duplicados → `Migrate` falla con `ErrDuplicateRoleCode` y `FindDuplicateRoleCodes` los nombra |
| `TestRevokeRoleByCodeInvalidatesCache` | **R-2, el central**: `HasPermission` → true, `RevokeRoleByCode`, `HasPermission` → false **en la misma instancia de `Service`** |
| `TestRevokeRoleByCodeIsIdempotent` | R-2: revocar dos veces no es error |
| `TestRevokeRoleByCodeUnknownCode` | R-2: `ErrRoleNotFound` |
| `TestAssignRoleByCodeDoesNotCreateRole` | R-2: code inexistente → `ErrRoleNotFound`, y la tabla `role` sigue vacía |
| `TestUsersInRole` | R-2: devuelve exactamente los ids asignados, y `[]` (no `nil` con error) para un rol sin usuarios |
| `TestRoleUserCount` | R-2 |
| `TestDeleteRoleUnknownReturnsNotFound` | R-3 |
| `TestDeleteRoleByCodeRemovesAssignments` | R-3: tras borrar, `UsersInRole` → `ErrRoleNotFound` y no quedan filas `UserRole` |

### Test consumer-shaped obligatorio

Regla de oro del harness: *an API is not published until a consumer-shaped
test, inside the library itself, proves it*. En `tests/revocation_test.go`:

```
TestAdminRevokesAccess_TakesEffectImmediately
```

Debe reproducir el flujo real del panel de `veltylabs/iam`, con el `Service`
real y la base en memoria:

1. Crear rol por `code`, asignarle un permiso, asignárselo a un usuario.
2. `HasPermission` → `true` (esto **puebla el caché**, que es el punto).
3. `RevokeRoleByCode` — la operación que el panel expone.
4. `HasPermission` → `false`, **sin recrear el `Service`**.

Ese test falla hoy si el consumidor borra la fila a mano, y es la prueba de
que el contrato nuevo es el que hay que usar.

## Restricciones de código (leer antes de escribir)

| Regla | Detalle |
|---|---|
| **Sin mapas** | Prohibido `map[K]V` en código de librería y en tests. Slices + búsqueda lineal. TinyGo compila mapas mal e infla el binario. **Ojo:** `FindDuplicateRoleCodes` se implementa con dos bucles sobre un slice, no con un `map[cacheKey]int`. |
| **Sin stdlib pesada** | Nada de `fmt`, `errors`, `strconv`, `strings`, `log`, `os`. Usa `github.com/tinywasm/fmt`. |
| **`error` sí, `errors` no** | `fmt.Err(...)`, nunca `errors.New`. |
| **Sin `reflect`** | Ni transitivo. |
| **Sin literales repetidos** | Todo string repetido (SQL, mensaje de error) es una constante nombrada. |
| **Sin `internal/`** | No crees carpetas `internal/`. |
| **`tests/` compila con Go estándar** | No está sujeto a las reglas de TinyGo. |
| **`orm` no cascadea** | El borrado manual de tablas de enlace en `DeleteRole` es deliberado. No lo quites. |

Idioma: **código e identificadores en inglés**; **comentarios de prosa y
documentación en español**.

## Etapa 5 · Documentación

- `docs/ARCHITECTURE.md`: sección **"`id` y `code`: dos identidades, un rol"**
  — el `id` es la clave del almacenamiento, el `code` es el vocabulario
  público; por qué `code` tiene que ser único dentro del proyecto y qué se
  rompía cuando no lo era.
- `docs/ARCHITECTURE.md`: sección **"El caché y por qué no se borra a mano"**
  — nombrar explícitamente el antipatrón `db.Delete(&rbac.UserRole{}, …)` y
  apuntar a `RevokeRoleByCode`.
- `README.md`: en la tabla de API, agregar los cuatro métodos nuevos con la
  fila "quiero X → uso Y".
- **BREAKING CHANGE** en el cuerpo del PR y arriba del README:
  `DeleteRole` pasa de devolver `nil` a devolver `ErrRoleNotFound` cuando el
  rol no existe.

## Criterios de aceptación

1. `go vet ./...` y `go test ./...` verdes.
2. `GOOS=js GOARCH=wasm go build ./...` compila.
3. `grep -rn "return roles\[0\], nil" rbac.go` → sólo tras el chequeo de
   `len(roles) > 1`.
4. `grep -rn "// Or ErrNotFound" .` → vacío.
5. `grep -rn "map\[" *.go` → vacío.
6. `RevokeRoleByCode`, `AssignRoleByCode`, `UsersInRole`, `RoleUserCount`,
   `DeleteRoleByCode`, `FindDuplicateRoleCodes`, `RoleCodeRef`,
   `ErrRoleNotFound`, `ErrDuplicateRoleCode` exportados y documentados en
   español.
7. `TestAdminRevokesAccess_TakesEffectImmediately` existe y pasa.
8. El PR describe el breaking change de `DeleteRole` en su cuerpo.

## Etapas

| # | Archivos | Entrega |
|---|---|---|
| 1 | `models.go`, `models_orm.go`, `migrate.go`, `rbac.go`, `errors.go` | `code` único por proyecto (R-1) |
| 2 | `rbac.go`, `errors.go` | Revocar/asignar/listar por `code` (R-2) |
| 3 | `rbac.go` | `DeleteRole` deja de devolver `nil` (R-3) |
| 4 | `tests/*` | Tests + consumer-shaped |
| 5 | `docs/ARCHITECTURE.md`, `README.md` | `id` vs `code`, caché, breaking change |
