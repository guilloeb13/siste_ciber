# Arquitectura de NavajaCyber

## Visión General

NavajaCyber es una plataforma modular de ciberseguridad que integra múltiples componentes para proporcionar capacidades de defensa, monitoreo, análisis y entrenamiento.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (React)                         │
│  Dashboard │ Findings │ Agents │ CTF │ Forensic                  │
└─────────────────────────┬───────────────────────────────────────┘
                          │ HTTP/WebSocket
┌─────────────────────────▼───────────────────────────────────────┐
│                      Backend (FastAPI)                           │
│  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌────────┐ ┌─────────────┐ │
│  │  Auth   │ │ Metrics  │ │Analysis │ │Forensic│ │     CTF     │ │
│  └────┬────┘ └────┬─────┘ └────┬────┘ └────┬───┘ └──────┬──────┘ │
│       │          │           │          │            │          │
│  ┌────▼──────────▼───────────▼──────────▼────────────▼────┐     │
│  │              Servicios Compartidos                      │     │
│  │  Database │ Redis │ MinIO │ Elasticsearch               │     │
│  └─────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
           ▲                    ▲                    ▲
           │ gRPC/HTTPS         │ HTTP               │ Docker API
    ┌──────┴──────┐      ┌──────┴──────┐      ┌──────┴──────┐
    │   Agents    │      │  Scanners   │      │CTF Challenges│
    │ Linux/Win   │      │Bandit/Semgrep│     │   Docker     │
    └─────────────┘      └─────────────┘      └─────────────┘
```

## Componentes Principales

### 1. Backend API (FastAPI)

**Responsabilidades:**
- API REST para todas las operaciones
- WebSocket para actualizaciones en tiempo real
- Autenticación y autorización (JWT/RBAC)
- Orquestación de servicios

**Tecnologías:**
- FastAPI 0.104+
- SQLAlchemy 2.0 (async)
- Pydantic 2.5+
- Uvicorn

**Endpoints principales:**
- `/api/auth/*` - Autenticación
- `/api/agents/*` - Gestión de agentes
- `/api/metrics/*` - Métricas
- `/api/findings/*` - Hallazgos de seguridad
- `/api/analysis/*` - Análisis de código
- `/api/forensic/*` - Operaciones forenses
- `/api/ctf/*` - CTF/Entrenamiento
- `/ws/*` - WebSocket streams

### 2. Agentes de Monitoreo

**Responsabilidades:**
- Recolección de métricas del sistema
- Chequeos de servicios
- Verificación de integridad
- Monitoreo de certificados

**Características:**
- Ligero y configurable
- Comunicación segura (HTTPS)
- Registro automático
- Heartbeat periódico

**Métricas recolectadas:**
- CPU (uso, frecuencia, por core)
- Memoria (total, usado, swap)
- Disco (por partición)
- Red (bytes, paquetes)
- Procesos (críticos)
- Servicios (HTTP latencia)
- Certificados (días restantes)
- Archivos (hashes)

### 3. Módulo de Análisis

**Responsabilidades:**
- Escaneo estático de código
- Análisis de dependencias
- Detección de secretos
- Normalización de resultados

**Herramientas integradas:**
- Bandit (Python)
- pip-audit (dependencias)
- Semgrep (opcional)
- Detector de secretos propio

**Flujo:**
```
Repo/Upload → Clone/Extract → Scan → Normalize → Store → Report
```

### 4. Módulo Forense

**Responsabilidades:**
- Recolección de evidencia
- Cálculo de hashes (integridad)
- Timeline de eventos
- Búsqueda de IOCs
- Cadena de custodia

**Artefactos soportados:**
- Logs del sistema (syslog, Windows Events)
- Capturas de red (pcap)
- Listas de procesos
- Conexiones de red
- Hashes del sistema de archivos

### 5. Módulo CTF

**Responsabilidades:**
- Gestión de retos
- Deployment de contenedores
- Validación de flags
- Scoring de equipos
- Aislamiento de red

**Características:**
- Retos basados en Docker
- Flags hasheados (SHA256)
- Red aislada para retos
- Límites de recursos

### 6. Frontend Dashboard

**Responsabilidades:**
- Visualización de métricas
- Lista de findings
- Gestión de agentes
- Interfaz CTF
- Alertas en tiempo real

**Tecnologías:**
- React 18
- TailwindCSS
- Recharts
- WebSocket client

## Flujo de Datos

### Métricas en Tiempo Real

```
Agent → HTTP POST /api/metrics/batch → Backend → Redis PubSub → WebSocket → Dashboard
```

### Análisis de Código

```
User → POST /api/analysis/scan → Background Task → Bandit/Semgrep → Findings → Database
```

### Validación de Flag CTF

```
Team → POST /api/ctf/submit → Hash Flag → Compare → Update Score → Broadcast WS
```

## Modelo de Datos

### Entidades Principales

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│    User     │       │    Agent    │       │   Finding   │
├─────────────┤       ├─────────────┤       ├─────────────┤
│ id          │       │ id          │       │ id          │
│ username    │       │ name        │       │ scan_id     │
│ email       │       │ hostname    │       │ source      │
│ role        │       │ status      │       │ severity    │
│ password    │       │ last_seen   │       │ title       │
└─────────────┘       └─────────────┘       │ file_path   │
                                            └─────────────┘

┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│   Metric    │       │  Challenge  │       │    Team     │
├─────────────┤       ├─────────────┤       ├─────────────┤
│ id          │       │ id          │       │ id          │
│ agent_id    │       │ name        │       │ name        │
│ type        │       │ category    │       │ score       │
│ name        │       │ points      │       │ token       │
│ value       │       │ flag_hash   │       │ members     │
└─────────────┘       └─────────────┘       └─────────────┘
```

## Seguridad

### Autenticación

- JWT tokens con expiración configurable
- Refresh tokens para sesiones largas
- OAuth2 password flow
- Bcrypt para hashing de contraseñas

### Autorización

- RBAC con 5 roles predefinidos
- Permisos granulares por endpoint
- Decoradores para validación

### Comunicación

- HTTPS obligatorio en producción
- WebSocket sobre TLS
- Validación de origen CORS

### Datos Sensibles

- Secrets nunca en código
- Variables de entorno / Vault
- Cifrado en reposo (opcional)

## Despliegue

### Desarrollo Local

```bash
docker-compose up --build
```

### Producción

Consideraciones:
- Usar secrets manager (Vault, AWS Secrets)
- Configurar SSL/TLS
- Habilitar backups automáticos
- Configurar rate limiting
- Implementar WAF
- Monitoreo externo

### Kubernetes (Guía general)

```yaml
# Ejemplo de deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: navaja-backend
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: backend
          image: navaja-cyber:latest
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: navaja-secrets
                  key: database-url
```

## Escalabilidad

### Horizontal

- Backend: Múltiples réplicas detrás de load balancer
- Workers: Cola de tareas con Celery/RQ (roadmap)
- Base de datos: Read replicas para consultas

### Vertical

- Aumentar recursos de contenedores
- Optimizar consultas de base de datos
- Cache agresivo en Redis

## Monitoreo

### Métricas de Aplicación

- Prometheus endpoint en `/metrics`
- OpenTelemetry (opcional)
- Structured logging con structlog

### Alertas Recomendadas

- CPU/Memoria del backend > 80%
- Errores 5xx > threshold
- Latencia P99 > 1s
- Cola de trabajos > 100

## Integración

### APIs Externas

- Webhooks para alertas
- Slack/Mattermost
- Email SMTP
- SIEM (Splunk, Elastic)

### Herramientas de Seguridad

- Trivy (contenedores)
- Gitleaks
- OWASP ZAP (roadmap)

## Roadmap Técnico

### Corto Plazo
- [ ] Cola de trabajos (Celery)
- [ ] Cache distribuido
- [ ] Métricas Prometheus mejoradas

### Mediano Plazo
- [ ] Integración SOAR
- [ ] Playbooks automatizados
- [ ] API GraphQL

### Largo Plazo
- [ ] ML para detección de anomalías
- [ ] Análisis de memoria (Volatility)
- [ ] Orquestación multi-nodo

---

Última actualización: Enero 2024
