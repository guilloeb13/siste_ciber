# NavajaCyber - Swiss-Army Cyber Toolkit

**USO AUTORIZADO ÚNICAMENTE**

NavajaCyber es una plataforma integral de ciberseguridad diseñada exclusivamente para defensa, monitoreo, análisis forense y capacitación (CTF) dentro de organizaciones autorizadas.

## Aviso Legal

```
Este software está diseñado exclusivamente para:
- Defensa y monitoreo de infraestructura propia
- Análisis forense con autorización explícita
- Capacitación en ciberseguridad (CTF)
- Análisis de código y dependencias

Cualquier uso no autorizado, intento de intrusión o explotación
contra sistemas externos sin permiso es ILEGAL.

El autor y proveedor del código NO se hacen responsables del uso indebido.
```

## Características

### 1. Monitoreo en Tiempo Real
- Agentes livianos para Linux/Windows
- Métricas de CPU, memoria, disco, red
- Chequeos de servicios HTTP/TCP
- Monitoreo de certificados TLS
- Verificación de integridad de archivos
- Dashboard con WebSocket en tiempo real

### 2. Análisis de Código y Dependencias
- Escaneo estático con Bandit y Semgrep
- Análisis de dependencias (pip-audit, safety)
- Detección de secretos en repositorios
- Reportes con CVSS, recomendaciones

### 3. Análisis de Bases de Datos
- Revisión de configuraciones inseguras
- Análisis de permisos y roles
- Detección de datos sensibles (PII)
- Solo análisis pasivo (modo lectura)

### 4. Módulo Forense
- Recolección de evidencia (logs, pcap)
- Cálculo de hashes para integridad
- Timeline forense
- Búsqueda de IOCs
- Cadena de custodia documentada

### 5. CTF / Entrenamiento
- Retos basados en Docker
- Sistema de scoring
- Gestión de equipos
- Validación segura de flags

## Requisitos

- Python 3.11+
- Docker y Docker Compose
- PostgreSQL 15+
- Redis 7+
- Node.js 20+ (para frontend)

## Instalación Rápida

### 1. Clonar el repositorio

```bash
git clone https://github.com/your-org/navaja-cyber.git
cd navaja-cyber
```

### 2. Configurar variables de entorno

```bash
cp .env.example .env
# Editar .env con tus configuraciones
```

### 3. Iniciar con Docker Compose

```bash
docker-compose up --build
```

### 4. Acceder a los servicios

- **Dashboard**: http://localhost:3000
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **MinIO Console**: http://localhost:9001

## Verificación de Instalación

### 1. Verificar servicios

```bash
# Health check del backend
curl http://localhost:8000/health

# Respuesta esperada:
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00",
  "version": "0.1.0",
  "checks": {
    "api": "ok",
    "database": "ok",
    "redis": "ok"
  }
}
```

### 2. Registrar un agente

```bash
python agents/linux_agent.py --register --backend http://localhost:8000

# Guardar el token devuelto
export AGENT_TOKEN="<token>"
export AGENT_ID="<id>"
```

### 3. Ejecutar un análisis

```bash
# Escanear un repositorio local
curl -X POST http://localhost:8000/api/analysis/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "scan_types": ["bandit", "pip-audit", "secrets"]
  }'

# Respuesta esperada:
{
  "scan_id": "uuid",
  "status": "queued",
  "message": "Scan has been queued for processing",
  "started_at": "2024-01-15T10:35:00"
}
```

### 4. Crear un reto CTF

```bash
# Crear un reto
curl -X POST http://localhost:8000/api/ctf/challenges \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SQL Injection 101",
    "description": "Find the vulnerability in the login form",
    "category": "web",
    "points": 100,
    "flag": "supersecretflag"
  }'
```

### 5. Validar un flag

```bash
curl -X POST http://localhost:8000/api/ctf/submit \
  -H "Content-Type: application/json" \
  -d '{
    "team_token": "team-token",
    "challenge_id": "challenge-uuid",
    "flag": "NAVAJA{supersecretflag}"
  }'

# Respuesta (correcta):
{
  "correct": true,
  "points": 100,
  "message": "Correct! Points awarded.",
  "new_score": 100
}
```

### 6. Ejecutar tests

```bash
# Instalar dependencias de desarrollo
pip install -e ".[dev]"

# Ejecutar tests
pytest tests/ -v

# Con cobertura
pytest tests/ -v --cov=backend --cov-report=html
```

## Estructura del Proyecto

```
navaja_cyber/
├── backend/
│   └── app/
│       ├── main.py           # FastAPI application
│       ├── config.py         # Settings
│       ├── models/           # SQLAlchemy models
│       ├── routers/          # API endpoints
│       └── services/         # Business logic
├── agents/
│   └── linux_agent.py        # Monitoring agent
├── analysis/
│   └── static_analysis.py    # Code scanning
├── forensic/
│   └── collector.py          # Evidence collection
├── ctf/
│   └── manager.py            # CTF challenge management
├── frontend/
│   └── src/
│       ├── App.jsx
│       └── components/
├── tests/
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
└── README.md
```

## API Endpoints Principales

### Autenticación
- `POST /api/auth/register` - Registrar usuario
- `POST /api/auth/token` - Obtener token JWT
- `GET /api/auth/me` - Usuario actual

### Agentes
- `POST /api/agents/register` - Registrar agente
- `GET /api/agents` - Listar agentes
- `POST /api/agents/{id}/heartbeat` - Heartbeat

### Métricas
- `POST /api/metrics` - Enviar métrica
- `POST /api/metrics/batch` - Enviar batch
- `GET /api/metrics` - Consultar métricas
- `GET /api/metrics/alerts` - Alertas activas

### Análisis
- `POST /api/analysis/scan` - Iniciar escaneo
- `GET /api/analysis/scan/{id}` - Estado del escaneo
- `POST /api/analysis/upload` - Subir y escanear

### Findings
- `GET /api/findings` - Listar findings
- `GET /api/findings/summary` - Resumen
- `PATCH /api/findings/{id}` - Actualizar estado

### Forense
- `POST /api/forensic/collect` - Subir evidencia
- `POST /api/forensic/ioc/search` - Buscar IOCs
- `GET /api/forensic/export/{case_id}` - Exportar caso

### CTF
- `POST /api/ctf/challenges` - Crear reto
- `GET /api/ctf/challenges` - Listar retos
- `POST /api/ctf/teams` - Crear equipo
- `POST /api/ctf/submit` - Enviar flag
- `GET /api/ctf/scoreboard` - Tabla de posiciones

### WebSocket
- `/ws/metrics` - Stream de métricas
- `/ws/alerts` - Stream de alertas
- `/ws/ctf` - Actualizaciones CTF

## Configuración del Agente

Crear archivo `/etc/navaja/agent.conf`:

```yaml
backend_url: http://navaja-server:8000
agent_id: <uuid>
agent_token: <token>
metric_interval: 30

# Procesos a monitorear
processes:
  - nginx
  - postgres
  - redis

# Servicios HTTP
services:
  - url: http://localhost/health
  - url: https://api.example.com/status

# Certificados TLS
certificates:
  - host: example.com
    port: 443

# Archivos para verificar integridad
file_integrity:
  - /etc/passwd
  - /etc/shadow
  - /usr/bin/sudo
```

## Roles y Permisos

| Rol       | Permisos                                    |
|-----------|---------------------------------------------|
| admin     | Acceso completo, gestión de usuarios        |
| analyst   | Análisis, findings, forense                 |
| operator  | Monitoreo, métricas, alertas                |
| auditor   | Lectura de reportes y evidencia             |
| trainer   | Gestión de CTF y retos                      |

## Roadmap

- [ ] Integración SOAR
- [ ] Playbooks de respuesta automatizada
- [ ] Integración SIEM (Splunk/Elastic)
- [ ] Análisis de memoria (Volatility)
- [ ] Orquestación con Ansible
- [ ] Dashboard de topología de red
- [ ] Alertas SMS/PagerDuty

## Contribuir

1. Fork el repositorio
2. Crear rama feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

## Soporte

Para reportar problemas o solicitar funcionalidades:
- Crear issue en GitHub
- Seguir la plantilla de issues

## Licencia

MIT License - Ver archivo LICENSE

---

**NavajaCyber v0.1.0** - Swiss-Army Cyber Toolkit
