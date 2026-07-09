# Revisión de Seguridad — NavajaCyber

> Revisión de código orientada a un estándar **grado militar** (defensa en
> profundidad, *fail-closed*, mínimo privilegio). Documenta las
> vulnerabilidades encontradas, las que se corrigieron en esta rama y las
> recomendaciones pendientes que requieren decisiones de arquitectura u
> operación.

Fecha: 2026-07-08 · Alcance: backend FastAPI, agente, módulos de análisis /
forense / CTF, e infraestructura (Docker/CI).

---

## Resumen ejecutivo

Se identificaron **varias vulnerabilidades críticas** que permitían, entre
otras cosas, ejecución remota de comandos, escalada de privilegios a
administrador y compromiso del host. La mayoría eran explotables por cualquier
usuario autenticado (o incluso sin autenticar). Esta rama corrige las de mayor
impacto y añade controles de defensa en profundidad y pruebas de regresión.

| # | Severidad | Vulnerabilidad | Estado |
|---|-----------|----------------|--------|
| 1 | **Crítica** | Escalada de privilegios: registro de usuario acepta `role` del cliente (auto-admin) | ✅ Corregida |
| 2 | **Crítica** | Inyección de comandos en `git clone` (shell + input sin validar) | ✅ Corregida |
| 3 | **Crítica** | Ejecución de contenedor sin restricción (`**docker_config`) → escape a host | ✅ Corregida |
| 4 | **Crítica** | Ingesta de métricas/heartbeat sin autenticación; token de agente nunca verificado | ✅ Corregida |
| 5 | **Alta** | `SECRET_KEY` débil por defecto → falsificación de JWT / bypass total de auth | ✅ Corregida (fail-closed en prod) |
| 6 | **Alta** | Zip Slip + zip bomb en subida de archivos | ✅ Corregida |
| 7 | **Alta** | Lectura de archivos arbitrarios vía `repo_path` (scan de `/etc`, secretos) | ✅ Corregida |
| 8 | **Alta** | WebSockets sin autenticación (fuga de métricas/alertas) | ✅ Corregida |
| 9 | **Alta** | CORS mal configurado (fallback a `*` con `credentials`) | ✅ Corregida |
| 10 | **Media** | SSRF en análisis de base de datos (loopback/metadata) | ✅ Mitigada |
| 11 | **Media** | Fuga de detalles internos en errores (DB analysis, CTF) | ✅ Corregida |
| 12 | **Media** | El detector de secretos almacenaba el secreto en claro | ✅ Corregida |
| 13 | **Media** | Comparación de flag no constante (timing) | ✅ Corregida |
| 14 | **Media** | Falta `TrustedHostMiddleware` (Host header / DNS rebinding) | ✅ Corregida |
| 15 | **Media** | Sin política de contraseñas (longitud mínima) | ✅ Corregida |
| 16 | **Media** | Rate limiting configurado pero **nunca aplicado** (fuerza bruta) | ✅ Corregida |
| 17 | **Media** | Docker socket = root en host (diseño CTF) | ✅ Mitigada (endpoint dedicado) |
| 18 | **Baja** | `python-jose`/`passlib` sin mantenimiento; sin fijado de dependencias | ✅ Corregida (PyJWT + Argon2) |
| 19 | **Baja** | Puertos de datos expuestos y credenciales por defecto en compose | ⚠️ Solo-dev |
| 20 | **Baja** | Carga de archivo completo en memoria (`await file.read()`) → DoS | ✅ Corregida (streaming) |
| 21 | **Media** | Sin bloqueo temporal de cuenta tras fallos de login | ✅ Corregida |
| 22 | **Baja** | Faltaban cabeceras de seguridad HTTP (CSP/HSTS/nosniff/frame) | ✅ Corregida |

---

## Vulnerabilidades corregidas (detalle)

### 1. Escalada de privilegios en el registro (Crítica)
`POST /api/auth/register` aceptaba el campo `role` del cuerpo de la petición
(`UserCreate.role`). Cualquiera podía registrarse como `admin`:

```json
{ "username": "x", "email": "x@x.com", "password": "...", "role": "admin" }
```

**Corrección** (`routers/auth.py`): se eliminó `role` del modelo de entrada. El
**primer** usuario registrado arranca como `ADMIN` (bootstrap); los demás
reciben el rol de **mínimo privilegio** (`OPERATOR`). Se añadió
`PATCH /api/auth/users/{id}/role` solo para administradores. Test:
`test_registration_ignores_client_role`.

### 2. Inyección de comandos en `git clone` (Crítica)
`run_scan_task` construía un comando shell por interpolación:
`f"git clone --depth 1 --branch {branch} {git_url} {target_path}"` y lo pasaba a
`create_subprocess_shell`. Un `git_url` como `"https://x/r; rm -rf / #"`
ejecutaba comandos arbitrarios (**RCE**).

**Corrección** (`routers/analysis.py` + `security.py`): validación estricta de
`git_url` y `branch` (esquemas `https/git/ssh`, sin metacaracteres, sin `-`
inicial) y ejecución con **lista de argumentos** (`create_subprocess_exec`,
nunca shell), con `--` separador y `GIT_TERMINAL_PROMPT=0`/`GIT_ASKPASS`.
Tests: `TestGitValidation`.

### 3. Ejecución de contenedores sin restricción (Crítica)
`activate_challenge` hacía `client.containers.run(image, **challenge.docker_config)`
con un diccionario controlado por el usuario (trainer). Permitía
`privileged=True`, montaje de `/`, `cap_add`, `pid_mode=host`, etc. →
**escape del contenedor y control del host** (más aún con el socket de Docker).

**Corrección** (`routers/ctf.py`): lista blanca de parámetros
(`environment`, `ports`, `mem_limit`, `cpu_quota`, `command`) y valores por
defecto endurecidos: `cap_drop=["ALL"]`,
`security_opt=["no-new-privileges:true"]`, `pids_limit`, límites de CPU/memoria.
Se dejó de devolver `str(e)` al cliente.

### 4. Ingesta de telemetría sin autenticación (Crítica)
`POST /api/metrics`, `/api/metrics/batch` y `/{id}/heartbeat` no requerían
autenticación y confiaban en el `agent_id` del cuerpo. El token generado al
registrar un agente **nunca se verificaba**. Cualquiera podía inyectar o
falsificar telemetría de cualquier agente.

**Corrección** (`routers/agents.py`, `routers/metrics.py`, `agents/linux_agent.py`):
dependencia `authenticate_agent` que valida cabeceras `X-Agent-Id` +
`X-Agent-Token` contra el hash almacenado (bcrypt, con `dummy_verify` para
mitigar enumeración por *timing*). Las métricas se atribuyen al **agente
autenticado** (se ignora el `agent_id` del cliente). El agente Linux ahora envía
esas cabeceras. Registro de agentes protegible con `AGENT_ENROLLMENT_TOKEN`.
Test: `test_metrics_ingestion_requires_agent_auth`.

### 5. `SECRET_KEY` débil → falsificación de JWT (Alta)
El valor por defecto (`change-this-...`) y los de `docker-compose`/CI eran
conocidos. Con HS256 y clave conocida, un atacante **forja cualquier JWT**
(incluido rol admin) → bypass total de autenticación.

**Corrección** (`config.py`): validador `model_validator` que **rechaza el
arranque** (fail-closed) si `APP_ENV=production` y la clave es un placeholder
conocido o mide <32 caracteres; también fuerza `DEBUG=false` y prohíbe CORS `*`
en producción. El JWT ahora incluye `iat` y usa tiempo *timezone-aware*.

### 6–7. Zip Slip / zip bomb y lectura de archivos arbitrarios (Alta)
`upload_and_scan` extraía el ZIP con `extractall` (Zip Slip) usando
`file.filename` sin sanear, sin límite de descompresión (zip bomb). `start_scan`
aceptaba `repo_path` arbitrario → escaneo de `/etc`, `/root`, etc.

**Corrección** (`security.py`, `routers/analysis.py`): `sanitize_filename`
(basename, sin traversal), `safe_zip_members` (rechaza rutas absolutas/`..` y
supera límite de tamaño descomprimido) y `resolve_within` para confinar
`repo_path` a `SCAN_BASE_DIR` (deshabilitado por defecto). Tests:
`TestSafeZipMembers`, `TestFilenameAndPaths`.

### 8. WebSockets sin autenticación (Alta)
`/ws/metrics`, `/ws/alerts`, `/ws/ctf` aceptaban cualquier conexión y emitían
métricas/alertas a cualquiera.

**Corrección** (`main.py`): `_authenticate_websocket` exige un JWT válido en el
parámetro `token` del handshake; cierra con código 1008 si falta o es inválido.

### 9 y 14. CORS y Host header (Alta/Media)
El CORS caía a `allow_origins=["*"]` **con** `allow_credentials=True` (config
inválida/insegura) y usaba hostnames en lugar de orígenes. No había validación
del `Host`.

**Corrección** (`main.py`, `config.py`): orígenes explícitos
(`CORS_ALLOW_ORIGINS`, con esquema y puerto); `allow_credentials` solo si hay
orígenes; métodos/cabeceras acotados. Se añadió `TrustedHostMiddleware` con
`ALLOWED_HOSTS`.

### 10–13. SSRF, fugas de error, secreto en claro, timing
- **SSRF** (`database_analysis.py`): `is_disallowed_target_host` bloquea
  loopback, link-local, multicast/reserved y el endpoint de metadata
  `169.254.169.254`; se validan `ssl_mode` y `port`.
- **Fugas**: los errores de conexión de BD y de arranque de contenedor CTF ya
  no devuelven `str(e)` al cliente; se registran en el log del servidor.
- **Secreto en claro** (`static_analysis.py`): el *snippet* del hallazgo
  redacta el valor coincidente (`[REDACTED_...]`).
- **Timing** (`ctf.py`, `ctf/manager.py`): comparación de flag con
  `hmac.compare_digest`.

---

### 16. Rate limiting aplicado (Media) — ✅ Corregida
Se integró `slowapi` (`backend/app/ratelimit.py`) y se registró el limitador,
su handler 429 y el middleware en `main.py`. Se aplican límites estrictos por
cliente en los endpoints sensibles: `/auth/token` (`RATE_LIMIT_AUTH`, 5/min por
defecto), `/auth/register` y `/agents/register` (`RATE_LIMIT_REGISTER`),
`/ctf/submit` (`RATE_LIMIT_SUBMIT`) y `/analysis/scan|upload`
(`RATE_LIMIT_SCAN`), además de un límite por defecto global. La clave de cuenta
usa la IP del cliente (o `X-Forwarded-For` solo si se confía en el proxy). Para
despliegues multi-worker, configurar `RATE_LIMIT_STORAGE_URI=redis://...` para
contadores compartidos. Test: `test_login_is_rate_limited`.

> Nota: el rate limiting reduce la fuerza bruta a nivel de red. Como refuerzo
> adicional (defensa en profundidad) sigue recomendándose un **bloqueo temporal
> de cuenta** tras N fallos de login por usuario (contador en Redis).

### 17. Aislamiento del runtime de CTF (Media) — ✅ Mitigada
Se añadió `CTF_DOCKER_HOST` (`config.py`) y tanto `routers/ctf.py` como
`ctf/manager.py` usan `docker.DockerClient(base_url=...)` para apuntar a un
daemon **dedicado/aislado** (rootless / Sysbox / gVisor / remoto) en lugar del
socket root del host. Sigue siendo responsabilidad operativa aprovisionar ese
daemon aislado; el código ya no obliga a compartir `docker.sock` con la API, y
los contenedores se lanzan con `cap_drop=ALL`, `no-new-privileges` y límites.

### 18. Cadena de suministro / dependencias (Baja) — ✅ Corregida
- Migrado de `python-jose` a **PyJWT** y de `passlib[bcrypt]` a **Argon2id**
  (`argon2-cffi`) mediante `backend/app/hashing.py`. Elimina la incompatibilidad
  con `bcrypt >= 4.1`, el límite de 72 bytes y dependencias sin mantenimiento.
- `pip-audit --strict` ahora **falla** el CI ante dependencias vulnerables
  (antes `|| true`); Bandit cubre todos los paquetes. Recomendación restante:
  fijar versiones con lockfile y firmar imágenes / SBOM.

### 20. Subidas por *streaming* (Baja) — ✅ Corregida
`stream_upload_to_path` (`security.py`) transmite la subida a disco por *chunks*
con corte temprano al superar el límite, calculando hashes de forma incremental.
Aplicado en `analysis.upload_and_scan` (límite `MAX_REPO_SIZE_MB`, 413 si excede)
y en `forensic.collect_evidence` (`EVIDENCE_MAX_MB`, subida a MinIO desde disco).

### 21. Bloqueo temporal de cuenta (Media) — ✅ Corregida
`backend/app/lockout.py` (respaldado por Redis) bloquea temporalmente una cuenta
tras `LOCKOUT_MAX_ATTEMPTS` fallos dentro de `LOCKOUT_WINDOW_SECONDS`. Se integra
en `/auth/token`; degrada a *no-op* si Redis no está disponible (el rate limiting
sigue protegiendo). Tests: `TestLockout`.

### 22. Cabeceras de seguridad HTTP (Baja) — ✅ Corregida
Middleware en `main.py` que añade `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, una CSP restrictiva,
`Permissions-Policy` y `Strict-Transport-Security` (fuera de desarrollo). Test:
`test_security_headers_present`.

## Pendiente / recomendaciones (requieren decisión)

### 19. Endurecer `docker-compose` para producción (Baja / solo-dev)
El compose actual es de desarrollo: expone Postgres/Redis/MinIO al host y usa
credenciales por defecto (`minioadmin`, `navaja_secret`). No usar tal cual en
producción; parametrizar todo por secretos y no publicar puertos de datos.

### Otras buenas prácticas sugeridas (backlog)
- **Auditoría inmutable**: registrar acciones sensibles (login, cambios de rol,
  exportación de evidencia) con cadena de custodia verificable.
- **Revocación de JWT** (lista de revocación en Redis) y *refresh tokens*.
- **Cifrado en reposo** de evidencia forense y de columnas PII detectadas.
- **`is_verified`** del usuario no se aplica en el login; considerar exigir
  verificación de correo antes de activar la cuenta.
- **Lockfile y SBOM** para fijar por completo la cadena de suministro.

---

## Cómo ejecutar las pruebas

```bash
pip install -e ".[dev]"
SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
DATABASE_URL="sqlite+aiosqlite:///./test.db" \
pytest tests/ -q
```

Las regresiones de seguridad viven en `tests/test_security.py`.
