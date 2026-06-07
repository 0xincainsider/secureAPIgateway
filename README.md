#  Secure API Gateway

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-00a393.svg)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-336791.svg)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-2496ED.svg)](https://docker.com)
[![Prometheus](https://img.shields.io/badge/Prometheus-E6522C.svg)](https://prometheus.io)
[![Grafana](https://img.shields.io/badge/Grafana-F46800.svg)](https://grafana.com)

A production-ready API Gateway with **authentication**, **rate limiting**, **observability**, and **OWASP-inspired security controls** built in from day one.

> **Security is not an afterthought — it's the foundation.**

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Security](#-security)
- [Observability](#-observability)
- [Testing](#-testing)
- [Project Structure](#-project-structure)
- [Roadmap](#-roadmap)
- [License](#-license)

---

## Overview

The **Secure API Gateway** is a comprehensive authentication and authorization gateway designed for modern web applications. It implements **JWT-based authentication** with OAuth2 Password Flow, **rate limiting** via Redis, **structured logging**, **full observability** with Prometheus and Grafana, and **OWASP-inspired security controls** throughout the entire stack.

Designed as a **portfolio project** for AppSec, Backend Security, and DevSecOps roles, it demonstrates professional-grade security engineering practices.

---

## 🏗 Architecture

```mermaid
graph TB
    Client[Client Application] -->|HTTPS| GW[API Gateway<br/>FastAPI]
    
    subgraph "API Gateway Container"
        GW --> Auth[Authentication Module]
        GW --> RL[Rate Limiter]
        GW --> Log[Logging Middleware]
        GW --> Sec[Security Middleware]
        GW --> Metrics[Metrics Exporter]
    end
    
    Auth --> DB[(PostgreSQL<br/>Users & Tokens)]
    RL --> Cache[(Redis<br/>Rate Limits & Blacklist)]
    
    Prom[Prometheus] -->|Scrape /metrics| Metrics
    Grafana[Grafana] -->|Query| Prom
    
    subgraph "Docker Services"
        DB
        Cache
        Prom
        Grafana
    end
    
    style Client fill:#f9f,stroke:#333,stroke-width:2px
    style GW fill:#58f,stroke:#333,stroke-width:2px
    style DB fill:#f96,stroke:#333,stroke-width:2px
    style Cache fill:#f96,stroke:#333,stroke-width:2px
    style Prom fill:#f96,stroke:#333,stroke-width:2px
    style Grafana fill:#f96,stroke:#333,stroke-width:2px
```


```mermaid
graph TD

    subgraph ExternalUsers["Acceso Externo"]
        User((Cliente / App))
        Admin((Administrador))
    end

    subgraph GatewayNetwork["Docker Network: gateway-network"]

        subgraph AppLayer["Capa de Aplicación"]
            API["FastAPI Gateway"]
        end

        subgraph StorageLayer["Capa de Persistencia"]
            DB[("PostgreSQL 16")]
            Redis[("Redis 7")]
        end

        subgraph MonitoringLayer["Capa de Monitoreo"]
            Prom["Prometheus"]
            Graf["Grafana"]
        end

    end

    User -->|Auth API :8000| API
    Admin -->|Grafana :3000| Graf

    API -->|Users & Audit Logs| DB
    API -->|Rate Limit & Blacklist| Redis

    Prom -->|Scrape /metrics| API
    Graf -->|Query| Prom
```

### Architecture Highlights

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **API Gateway** | FastAPI (Python) | Request handling, routing, validation |
| **Database** | PostgreSQL 16 | Persistent user/token/audit storage |
| **Cache** | Redis 7 | Rate limiting, token blacklist |
| **Monitoring** | Prometheus | Metrics collection and querying |
| **Visualization** | Grafana | Dashboard for metrics visualization |
| **Containerization** | Docker Compose | Full-stack orchestration |

---

## ✨ Features

### Authentication & Authorization
- ✅ **JWT-based authentication** (HS256 signed tokens)
- ✅ **OAuth2 Password Flow** (Swagger UI compatible)
- ✅ **Access tokens** (15 min expiry) + **Refresh tokens** (7 day expiry)
- ✅ **Token revocation** via Redis blacklist + database
- ✅ **Refresh token rotation** (old token revoked on refresh)
- ✅ **Secure password storage** (bcrypt, 12 rounds)
- ✅ **User registration** with strong password validation
- ✅ **User enumeration protection** (generic error messages)

### Rate Limiting
- ✅ **IP-based rate limiting** (100 requests/minute default)
- ✅ **User-based rate limiting** (200 requests/minute for authenticated users)
- ✅ **Redis backend** for fast, atomic operations
- ✅ **HTTP 429 responses** with `Retry-After` headers
- ✅ **Fail-open** behavior when Redis is unavailable

### Security
- ✅ **OWASP Security Headers**: CSP, HSTS, XFO, X-Content-Type-Options, etc.
- ✅ **Input validation**: Strong Pydantic schemas with custom validators
- ✅ **Password strength enforcement**: ≥8 chars, upper, lower, digit, special
- ✅ **SQL injection prevention**: Parameterized queries via SQLAlchemy ORM
- ✅ **Request validation**: Body size limits, path traversal detection
- ✅ **Audit logging**: Database-backed security event audit trail
- ✅ **No sensitive info in responses**: Passwords, tokens never exposed
- ✅ **Non-root Docker user**: Principle of least privilege

### Observability
- ✅ **Structured JSON logging** with request tracing
- ✅ **Prometheus metrics**: Request rate, latency, errors, auth events
- ✅ **Grafana dashboard**: Traffic, latency, anomalies, auth events, errors
- ✅ **Health check endpoint** for orchestration
- ✅ **Request ID tracking** across the request lifecycle

### DevOps
- ✅ **Docker multi-stage build** (optimized production image)
- ✅ **Docker Compose** for full-stack orchestration
- ✅ **Environment-based configuration** (12-factor app)
- ✅ **Health checks** for all services

---

## 🛠 Tech Stack

| Category | Technologies |
|----------|-------------|
| **Backend Framework** | FastAPI 0.115+ |
| **Language** | Python 3.12+ |
| **Database** | PostgreSQL 16 (async via asyncpg + SQLAlchemy) |
| **Cache** | Redis 7 (async via redis-py) |
| **Authentication** | JWT (PyJWT), OAuth2 Password Flow, bcrypt |
| **Validation** | Pydantic V2 (strict mode) |
| **Testing** | pytest, pytest-asyncio, httpx |
| **Monitoring** | Prometheus, Grafana |
| **Containerization** | Docker, Docker Compose |
| **Migrations** | Alembic |

---

## 🚀 Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (20.10+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2.0+)
- [Git](https://git-scm.com/)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-api-gateway.git
cd secure-api-gateway

# Configure environment (optional - defaults work for local dev)
cp .env.example .env

# Start all services
docker compose up -d

# Verify services are healthy
docker compose ps
```

### Access the Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **API Gateway** | http://localhost:8000 | - |
| **Swagger UI** | http://localhost:8000/api/v1/docs | - |
| **ReDoc** | http://localhost:8000/api/v1/redoc | - |
| **Prometheus** | http://localhost:9090 | - |
| **Grafana** | http://localhost:3000 | admin / admin |
| **PostgreSQL** | localhost:5432 | gateway / gateway_secret |
| **Redis** | localhost:6379 | - |

### Quick API Test

```bash
# Run the API examples script
chmod +x docs/api-examples.sh
./docs/api-examples.sh
```

Or manually:

```bash
# Register a user
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","username":"demo","password":"SecurePass123!","display_name":"Demo User"}'

# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=demo&password=SecurePass123!"

# Access protected endpoint (replace TOKEN with actual token)
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer TOKEN"
```

---

## ⚙️ Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and customize:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | (change me) | JWT signing key |
| `DATABASE_URL` | postgresql+asyncpg://... | PostgreSQL connection |
| `REDIS_URL` | redis://redis:6379/0 | Redis connection |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | 15 | Access token TTL |
| `REFRESH_TOKEN_EXPIRE_DAYS` | 7 | Refresh token TTL |
| `RATE_LIMIT_DEFAULT` | 100 | IP-based rate limit per window |
| `RATE_LIMIT_PER_USER` | 200 | User-based rate limit per window |
| `RATE_LIMIT_WINDOW_SECONDS` | 60 | Rate limit window |
| `BCRYPT_ROUNDS` | 12 | Password hashing cost factor |
| `LOG_LEVEL` | INFO | Logging level |
| `ENABLE_RATE_LIMIT` | true | Toggle rate limiting |
| `ENABLE_SECURITY_HEADERS` | true | Toggle security headers |
| `PROMETHEUS_ENABLED` | true | Toggle metrics export |

> **⚠️ Security**: Never commit the `.env` file. In production, use a secrets manager.

---

## 📚 API Reference

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|:---:|
| `POST` | `/api/v1/auth/register` | Register a new user | ❌ |
| `POST` | `/api/v1/auth/login` | Login (OAuth2 Password Flow) | ❌ |
| `POST` | `/api/v1/auth/refresh` | Refresh tokens | ❌ |
| `POST` | `/api/v1/auth/logout` | Logout (revoke tokens) | ✅ |
| `GET` | `/api/v1/auth/me` | Get current user profile | ✅ |

### Other Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/api/v1/docs` | Swagger UI documentation |
| `GET` | `/api/v1/redoc` | ReDoc documentation |

### Request/Response Examples

<details>
<summary><b>Register</b></summary>

```http
POST /api/v1/auth/register
Content-Type: application/json

{
    "email": "alice@example.com",
    "username": "alice",
    "password": "StrongPass123!",
    "display_name": "Alice Johnson"
}
```

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "alice@example.com",
    "username": "alice",
    "display_name": "Alice Johnson",
    "is_active": true,
    "is_verified": false,
    "created_at": "2024-01-01T00:00:00Z"
}
```
</details>

<details>
<summary><b>Login</b></summary>

```http
POST /api/v1/auth/login
Content-Type: application/x-www-form-urlencoded

username=alice&password=StrongPass123!
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "bearer",
    "expires_in": 900
}
```
</details>

<details>
<summary><b>Get Profile</b></summary>

```http
GET /api/v1/auth/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "alice@example.com",
    "username": "alice",
    "display_name": "Alice Johnson",
    "is_active": true,
    "is_verified": true,
    "created_at": "2024-01-01T00:00:00Z"
}
```
</details>

---

## 🛡 Security

The gateway implements **14+ security controls** from the OWASP Top 10 and beyond. See [docs/security-decisions.md](docs/security-decisions.md) for the complete security architecture document.

### Key Security Features

| Feature | Implementation | OWASP Reference |
|---------|---------------|-----------------|
| **Secure Password Storage** | bcrypt (12 rounds) via passlib | [Password Storage CS](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) |
| **JWT Validation** | Signature, expiry, issuer, audience, type | [JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) |
| **Rate Limiting** | Redis-based, IP and user scoped | [DoS Prevention CS](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) |
| **Security Headers** | CSP, HSTS, XFO, X-Content-Type-Options | [HTTP Headers CS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| **Input Validation** | Pydantic V2 with custom validators | [Input Validation CS](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) |
| **Audit Logging** | JSON structured + DB audit trail | [Logging CS](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) |
| **Error Handling** | No sensitive info in errors | [Error Handling CS](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) |
| **Token Revocation** | Redis blacklist + DB revocation | [Session Mgmt CS](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |

---

## 📊 Observability

### Prometheus Metrics

The gateway exposes metrics at `GET /metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `http_requests_total` | Counter | Total requests by method, endpoint, status |
| `http_request_duration_seconds` | Histogram | Request latency distribution |
| `auth_login_success_total` | Counter | Successful logins |
| `auth_login_failure_total` | Counter | Failed logins |
| `rate_limit_blocked_total` | Counter | Rate-limited requests |
| `active_connections` | Gauge | Current active connections |

### Grafana Dashboard

The auto-provisioned dashboard includes:

- **Traffic Overview**: Requests per second, error rate, active connections
- **Request Rate by Endpoint**: Bar gauge of request distribution
- **Latency Analysis**: P50, P99, and average latency time series
- **Authentication Events**: Login success/failure rate
- **Error Tracking**: HTTP error rate by status code
- **Rate Limit Events**: Blocked requests monitoring

Access Grafana at [http://localhost:3000](http://localhost:3000) (admin / admin).

![Grafana Dashboard Preview](docs/images/dashboard-preview.png)
*Note: Add a screenshot of the dashboard once running*

---

## 🧪 Testing

### Running Tests

```bash
# Install test dependencies
pip install -r requirements.txt

# Run all tests with coverage
pytest tests/ -v --cov=app --cov-report=term-missing

# Run specific test categories
pytest tests/unit/ -v       # Unit tests (10+ tests)
pytest tests/integration/ -v  # Integration tests (5+ tests)
pytest tests/security/ -v    # Security tests (5+ tests)
```

### Test Coverage

| Category | Tests | Description |
|----------|-------|-------------|
| **Unit Tests** | 10+ | Password hashing, JWT tokens, schema validation |
| **Integration Tests** | 5+ | API endpoints, authentication flows, error handling |
| **Security Tests** | 5+ | JWT bypass, rate limiting, token revocation, weak passwords |

---

## 📁 Project Structure

```
secure-api-gateway/
├── app/                          # Application source code
│   ├── api/v1/                   # API route handlers
│   │   └── auth.py               # Authentication endpoints
│   ├── core/                     # Core configuration
│   │   ├── config.py             # Pydantic Settings
│   │   ├── dependencies.py       # FastAPI dependencies
│   │   └── security.py           # Password hashing utilities
│   ├── database/                 # Database configuration
│   │   └── session.py            # Async SQLAlchemy session
│   ├── middleware/                # Middleware components
│   │   ├── logging.py            # Structured request logging
│   │   └── security.py           # Security headers & validation
│   ├── models/                   # SQLAlchemy ORM models
│   │   ├── user.py               # User model
│   │   ├── refresh_token.py      # RefreshToken model
│   │   └── audit_log.py          # AuditLog model
│   ├── schemas/                  # Pydantic schemas
│   │   └── auth.py               # Auth request/response schemas
│   ├── security/                 # Security components
│   │   ├── jwt.py                # JWT token management
│   │   ├── rate_limiter.py       # Redis-based rate limiting
│   │   └── token_blacklist.py    # Token revocation via Redis
│   ├── services/                 # Business logic layer
│   │   └── auth_service.py       # Authentication service
│   ├── utils/                    # Utility modules
│   │   └── logger.py             # JSON structured logger
│   └── main.py                   # FastAPI application entry point
├── tests/                        # Test suite
│   ├── unit/                     # Unit tests (10+)
│   ├── integration/              # Integration tests (5+)
│   ├── security/                 # Security tests (5+)
│   └── conftest.py               # Test fixtures
├── docker/                       # Docker configuration
│   ├── prometheus/               # Prometheus scrape config
│   └── grafana/                  # Grafana provisioning & dashboards
├── docs/                         # Documentation
│   ├── security-decisions.md     # Security architecture document
│   └── api-examples.sh           # curl API usage examples
├── migrations/                   # Alembic migration scripts
├── Dockerfile                    # Multi-stage Docker build
├── docker-compose.yml            # Full-stack orchestration
├── requirements.txt              # Python dependencies
├── alembic.ini                   # Alembic configuration
├── .env.example                  # Environment template
└── README.md                     # This file
```

---

## 🗺 Roadmap

- [ ] **OAuth2 Authorization Code Flow** with social login (Google, GitHub)
- [ ] **API Key management** for machine-to-machine authentication
- [ ] **Webhook signature verification**
- [ ] **Advanced rate limiting** (sliding window, token bucket)
- [ ] **Alertmanager integration** for alerting on security events
- [ ] **OWASP ZAP integration** for automated security scanning
- [ ] **SQLAlchemy 2.0 migrations** with full Alembic workflow
- [ ] **Kubernetes deployment manifests** (Helm charts)
- [ ] **End-to-end encryption** support (client-side encryption)
- [ ] **Compliance reports** (GDPR, SOC2 audit trail exports)
- [ ] **CI/CD pipeline** (GitHub Actions with security scanning)
- [ ] **Terraform infrastructure** for cloud deployment

 