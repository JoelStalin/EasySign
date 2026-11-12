# PostgreSQL con aislamiento por empresa (ES-006)

Estado: **dos libros migrados (consentimientos y auditoría)**. El registro de certificados y las solicitudes de firma siguen en archivo JSONL o memoria; ver "Siguientes pasos".

## Qué hay

| Pieza | Dónde | Qué hace |
|---|---|---|
| Interfaz `LedgerStore` | `src/storage/ledger-store.ts` | `append(tenantId, evento)`, `readAll(tenantId)` y `verify(tenantId?)` para un libro encadenado por SHA-256. Una instancia por libro. |
| `FileLedgerStore` | mismo archivo | El comportamiento de siempre: memoria, o JSONL si se da una ruta. Lee y verifica toda la cadena al crearse. El formato de línea no cambió, así que los archivos anteriores se cargan igual. |
| `PostgresLedgerStore` | `src/storage/postgres-ledger-store.ts` | Paquete `pg`. Cada operación abre una transacción, fija `app.tenant_id` y solo entonces consulta. |
| Migraciones | `migrations/NNN_nombre.sql`, `src/storage/migrate.ts` | Versionadas, una transacción por archivo, registradas en `schema_migrations` con su SHA-256. |
| Comandos | `npm run migrate`, `npm run ledger:verify` | Aplicar migraciones y verificar la cadena completa. |
| Libro de consentimientos | `src/services/consent-ledger.ts` | Ahora es asíncrono y usa un `LedgerStore`. |
| Libro de auditoría | `src/services/audit-log.ts` | Ídem. Las líneas JSONL conservan sus campos de siempre. |

## Modelo de datos

```sql
ledger_events(ledger text, seq bigint, tenant_id text, type text, at timestamptz,
              payload jsonb, prev_hash text, hash text, PRIMARY KEY (ledger, seq))
ledger_heads(ledger text PRIMARY KEY, last_seq bigint, last_hash text)
```

- La cadena es **una por libro y abarca todas las empresas**, igual que el JSONL: `seq` va de 1 a n y cada evento guarda el hash del anterior. El hash se calcula con la misma fórmula que antes.
- `ledger_heads` guarda el último número y el último hash de cada libro. No tiene datos de ninguna empresa.
- Un disparador (`ledger_events_extend_chain`) acepta un evento solo si continúa la cabeza actual (`seq = last_seq + 1` y `prev_hash = last_hash`). Si otro escritor se adelantó responde `40001` y la aplicación relee la cabeza y reintenta. La aplicación además toma un bloqueo consultivo por libro para no chocar.
- La tabla es **solo de inserción**: otro disparador rechaza `UPDATE`, `DELETE` y `TRUNCATE` para cualquiera, incluido el dueño del esquema.

## Aislamiento por empresa

- `ledger_events` tiene `ENABLE` y `FORCE ROW LEVEL SECURITY`. Las políticas `tenant_read` y `tenant_append` exigen `tenant_id = current_setting('app.tenant_id', true)` y están concedidas solo al rol `easysign_app`.
- `app.tenant_id` se fija **por transacción** con `set_config('app.tenant_id', $1, true)`, que es `SET LOCAL` con parámetro. Al terminar la transacción el valor desaparece: la siguiente petición que reciba esa conexión del pool no hereda la empresa anterior. Sin valor, o con valor vacío, no se ve ni se escribe ninguna fila.
- Roles (los crea la migración, sin inicio de sesión):
  - `easysign_app`: `SELECT` e `INSERT` sobre `ledger_events`, `SELECT` sobre `ledger_heads`. Sin `BYPASSRLS`, sin ser dueño, sin `UPDATE`/`DELETE`/`TRUNCATE`.
  - `easysign_auditor`: solo lectura de todas las empresas, para verificar la cadena completa y exportar evidencia. El proceso de la API nunca lo usa.
  - El dueño del esquema ejecuta las migraciones. Con `FORCE`, ni siquiera él ve filas de empresas.
- **La API se niega a trabajar con un rol inseguro.** Antes de cada operación (y al arrancar, en `onReady`) comprueba que el rol conectado no sea superusuario, no tenga `BYPASSRLS`, no sea dueño de la tabla, no sea miembro de `easysign_auditor`, no pueda modificar ni borrar, y que la tabla tenga RLS activado y forzado. Si algo falla lanza `UnsafeDatabaseRoleError` y el servidor no arranca.

### Qué puede saber una empresa de las demás

Solo lo que revela `ledger_heads`: cuántos eventos tiene el libro en total y el hash del último. También puede deducir, por los saltos en sus propios `seq`, que hubo actividad ajena. No puede saber de quién, ni el contenido. Es el precio de mantener una sola cadena; si se quiere eliminar, la alternativa es una cadena por empresa (cambia la fórmula de `seq` y el formato de evidencia, por eso no se hizo aquí).

## Libro de auditoría sobre PostgreSQL

- Los eventos de plataforma (trabajos de la cola sin empresa, peticiones sin empresa) se guardan con `tenant_id = 'platform'`, que para el RLS es una empresa más.
- **Con PostgreSQL toda lectura necesita empresa.** `GET /v1/audit/events` sin `tenantId` responde `400 TENANT_REQUIRED`, también para `platform_admin`. Con archivo o memoria sigue devolviendo todas las empresas, como antes. La revisión de todas las empresas a la vez se hace con el rol auditor, fuera de la API.
- `details` es un objeto libre. Antes de calcular el hash se ordenan sus claves en todos los niveles y se quitan los caracteres NUL, porque `jsonb` no conserva el orden ni admite NUL. En archivo se mantiene el orden original.
- El paquete de evidencia (`POST /v1/audit/export`) sigue anclado al hash de la cabeza del libro entero, que ahora sale de `ledger_heads`. Si la cadena de esa empresa está alterada, el paquete sale con `chainValid: false` y sin eventos.
- El registro de cada petición se escribe después de enviar la respuesta. Si la base falla en ese momento, la petición ya respondió y el evento se pierde sin aviso al cliente. Conviene vigilar los errores de conexión de la API.

## Verificación de la cadena

- **Al leer** (`readAll`, que usan todas las consultas del libro): se recalcula el hash de cada evento visible, se exige orden creciente, se comprueba el enlace entre eventos consecutivos visibles y que el último no contradiga la cabeza. Si algo no cuadra, `LedgerChainError` → `ConsentError CHAIN_BROKEN` (HTTP 500).
- **Límite:** con el rol de la aplicación una empresa no ve la cadena entera, así que no puede detectar por sí sola que falte un evento suyo en medio. Eso lo detecta la verificación completa.
- **Cadena completa:** `npm run ledger:verify` con `EASYSIGN_AUDIT_DATABASE_URL` (rol miembro de `easysign_auditor`). Recorre todo el libro, cada enlace y la cabeza. Conviene programarlo (por ejemplo cada hora) y alertar si falla.
- El archivo JSONL sigue verificándose completo al arrancar, como antes.

## Puesta en marcha

Las contraseñas no van en el repositorio; se generan en el servidor y se guardan en el gestor de secretos.

```sql
-- una vez, como superusuario
CREATE ROLE easysign_owner LOGIN CREATEROLE PASSWORD '...';
CREATE DATABASE easysign OWNER easysign_owner;
```
```bash
EASYSIGN_MIGRATION_DATABASE_URL=postgres://easysign_owner:...@host/easysign npm run migrate
```
```sql
-- después de la primera migración, como superusuario
CREATE ROLE easysign_api   LOGIN PASSWORD '...' IN ROLE easysign_app;
CREATE ROLE easysign_audit LOGIN PASSWORD '...' IN ROLE easysign_auditor;
```

| Variable | Rol | Uso |
|---|---|---|
| `EASYSIGN_DATABASE_URL` | `easysign_api` | La API. Si falta, los libros usan `EASYSIGN_CONSENT_FILE` y `EASYSIGN_AUDIT_FILE` o memoria, como hasta ahora. Si está, **tiene prioridad** sobre los archivos. |
| `EASYSIGN_DATABASE_POOL_MAX` | | Conexiones del pool (10 por defecto). |
| `EASYSIGN_MIGRATION_DATABASE_URL` | `easysign_owner` | Solo `npm run migrate`. |
| `EASYSIGN_AUDIT_DATABASE_URL` | `easysign_audit` | Solo `npm run ledger:verify`. |
| `EASYSIGN_TEST_DATABASE_URL` | superusuario de un servidor **desechable** | Solo pruebas de integración. |

Una migración ya aplicada no se edita: el ejecutor compara el SHA-256 y se detiene. Los cambios van en un archivo nuevo con el número siguiente.

**No hay importación automática del JSONL.** Si ya existe un `consents.jsonl` o un `audit.jsonl` con datos, hay que cargarlo antes de activar la base (pendiente, ver abajo); mientras tanto no se deben activar las dos cosas a la vez esperando que se fusionen.

## Pruebas

- Siempre: `src/ledger-store.test.ts` (almacén en memoria y archivo, vista parcial por empresa, compatibilidad con archivos anteriores, orden de claves tras `jsonb`, numeración de migraciones) y las de consentimientos ya existentes, ahora asíncronas.
- Integración: `src/postgres-ledger.test.ts`. Se saltan si no hay `EASYSIGN_TEST_DATABASE_URL`. La suite crea su propia base y sus roles con nombre aleatorio y los borra al final.

```bash
docker run -d --name easysign-pgtest-x -e POSTGRES_PASSWORD=$(openssl rand -hex 16) -p 127.0.0.1::5432 postgres:16
EASYSIGN_TEST_DATABASE_URL=postgres://postgres:<clave>@127.0.0.1:<puerto>/postgres npm test
docker rm -f -v easysign-pgtest-x
```

Lo que demuestran, con SQL directo bajo el rol de la aplicación:

- Sin `app.tenant_id` no se ve ninguna fila; con el de la empresa B no aparece ninguna de A, se filtre como se filtre.
- El valor no se queda pegado a la conexión del pool entre transacciones.
- Insertar una fila con el `tenant_id` de otra empresa falla (`42501`). También fallan `UPDATE`, `DELETE`, `TRUNCATE`, `SELECT ... FOR UPDATE`, tocar `ledger_heads`, `SET row_security = off`, `SET ROLE`, desactivar RLS o los disparadores y crear o borrar políticas.
- Un evento que no continúa la cabeza es rechazado por la base (`40001`).
- 60 escrituras concurrentes de tres empresas desde dos instancias dejan una cadena sin huecos ni duplicados, verificada entera con el rol auditor.
- El rol de la aplicación no puede verificar ni leer la cadena completa; el auditor no puede escribir; el dueño y el superusuario son rechazados por la API.
- Una alteración hecha con privilegios de superusuario se detecta al leer (`CHAIN_BROKEN`) y en la verificación completa, sin afectar a las demás empresas.

## Límites declarados

- Solo los libros de consentimientos y auditoría usan PostgreSQL. El registro de certificados y las solicitudes de firma siguen en JSONL o memoria.
- Cada consulta del libro lee todos los eventos de esa empresa y los verifica. Es correcto con varias instancias y suficiente para el volumen actual; con mucho volumen hará falta una proyección (tabla de estado vigente) o verificación incremental.
- `withdraw` consulta y luego inserta en transacciones distintas: dos retiros simultáneos del mismo consentimiento pueden dejar dos eventos `withdrawn`. El estado resultante es el mismo (sin consentimiento).
- En el flujo de firma, la aceptación se registra primero en el libro de solicitudes (todavía en memoria/archivo) y después en el de consentimientos. Si la base falla en medio, la petición responde 500 y queda el primer registro sin el segundo. Se resuelve cuando ambos libros estén en la misma base y transacción.
- **El aislamiento depende de quién fija `app.tenant_id`.** La empresa sale de un parámetro de sesión, tal como pide el diseño (`SET LOCAL`). Quien pueda ejecutar SQL arbitrario con la credencial de `easysign_api` (credencial filtrada o inyección de SQL) puede poner el identificador de cualquier empresa y leer o añadir eventos en su nombre. Lo que el RLS sí garantiza es que una consulta de la aplicación que olvide filtrar, o que corra sin empresa, no devuelve nada ajeno. Mitigaciones actuales: todas las consultas son parametrizadas, la empresa viene del token verificado, y la credencial solo la tiene la API. Para cerrar el hueco del todo haría falta un rol de base por empresa o firmar el identificador (pendiente de decidir).
- **La base no recalcula el SHA-256.** El disparador exige que cada evento continúe la cabeza, pero no puede comprobar que `hash` corresponda al contenido. Un `INSERT` directo con un hash inventado entra y se detecta después (al leer esa empresa y en `ledger:verify`), no antes. Como la tabla es solo de inserción, corregirlo exige intervención del administrador.
- El RLS protege frente a errores y consultas de la aplicación. No protege frente a quien tenga superusuario en el servidor: eso se detecta (cadena de hashes) pero no se impide. Copias de seguridad, cifrado en reposo y TLS de la conexión son tarea de despliegue y no están configurados aquí.
- Los datos personales de la evidencia (IP, agente de usuario) siguen en un registro inmutable; la política de retención de la Ley 172-13 sigue pendiente con el abogado.

## Siguientes pasos (un PR por libro)

1. **Auditoría: hecha.** Queda decidir si `platform_admin` necesita una consulta de todas las empresas dentro de la API (hoy no la tiene con PostgreSQL).
2. **Registro de certificados** (`certificate-registry.ts`). La consulta pública de estado no lleva empresa: necesita una política de lectura propia o una vista publicada.
3. **Solicitudes de firma** (`signature-workflow.ts`). El firmante entra con un token, sin identidad de empresa: la búsqueda por id de solicitud tiene que resolver la empresa antes de fijar `app.tenant_id` (función `SECURITY DEFINER` acotada o tabla índice id → empresa).
4. Importador de JSONL existente a PostgreSQL, conservando `seq` y hashes.
5. Documentos: almacenamiento de objetos o `bytea` con hash.

## Cómo revertir

Quitar `EASYSIGN_DATABASE_URL` devuelve la API al archivo o a memoria sin tocar código. Para deshacer el cambio, `git revert` de los commits de la rama `feat/easysign-pg-tenant-store`. La base se elimina con `DROP DATABASE` (los eventos guardados allí se pierden: exportarlos antes con el rol auditor).
