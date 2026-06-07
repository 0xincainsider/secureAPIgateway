# Security Decisions Document

## Secure API Gateway

This document explains every security-related design decision made in the Secure API Gateway project. Each decision includes the rationale, alternatives considered, and relevant OWASP references.

---

## 1. Password Hashing: bcrypt via passlib

**Decision:** Use bcrypt (via passlib) with 12 rounds for password hashing.

**Rationale:**
- bcrypt is a well-vetted, adaptive hashing function designed specifically for password storage.
- The cost factor (rounds) is configurable and can be increased as hardware improves.
- passlib provides a clean abstraction and automatic salt generation.
- Argon2 was considered but bcrypt was chosen for broader library support and established track record.
- 12 rounds provides ~250ms hash time on modern hardware, balancing security and UX.

**Alternatives Considered:**
- **Argon2id**: More resistant to side-channel and GPU attacks, but less widespread library support.
- **SHA-256 (salted)**: Rejected because it's designed for speed, making it vulnerable to brute force.
- **Plain text**: Rejected due to obvious security implications.

**OWASP Reference:**
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

## 2. Token Format: JWT with RS256/HS256

**Decision:** Use JSON Web Tokens (JWT) signed with HMAC-SHA256 (HS256).

**Rationale:**
- JWT provides a self-contained, stateless authentication mechanism.
- HS256 (symmetric) is appropriate for a single-service architecture.
- Tokens include standard claims (iss, aud, sub, exp, iat, jti) for validation.
- JWT ID (jti) enables token-level revocation tracking.

**Security Measures:**
- Access tokens expire after 15 minutes (short-lived to limit exposure).
- Refresh tokens expire after 7 days (longer-lived but revocable).
- Tokens are validated for: signature, expiration, issuer, audience, and token type.
- All required claims are verified before any operation.

**Alternatives Considered:**
- **Session-based auth (server-side sessions)**: More control but requires session storage and is not stateless.
- **PASETO**: More modern and secure token format, but less ecosystem support.
- **OAuth2 opaque tokens**: Better for distributed systems, but adds complexity for a single gateway.

**OWASP Reference:**
- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

## 3. Token Revocation: Redis-based Blacklist

**Decision:** Use Redis to maintain a blacklist of revoked token JTIs with TTL.

**Rationale:**
- Redis provides fast, in-memory lookups for token validation on every request.
- Automatic TTL ensures blacklist entries expire when the token would have expired naturally.
- Singleton pattern prevents the blacklist from growing unbounded.
- Token rotation (issuing new refresh token on refresh) invalidates old tokens.

**Security Measures:**
- When a token is revoked, its JTI is stored in Redis with TTL matching remaining token lifetime.
- On logout, all refresh tokens for a user are revoked in the database and Redis.
- Token rotation ensures each refresh token can only be used once.

**Alternatives Considered:**
- **Database-only blacklist**: More durable but slower for high-frequency validation.
- **Token version number in database**: Requires DB query on every request.
- **No revocation**: Rejected because it prevents logout functionality.

**OWASP Reference:**
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

## 4. Rate Limiting: Redis Fixed Window

**Decision:** Implement rate limiting using Redis INCR with fixed window counters.

**Rationale:**
- Redis provides atomic increment operations (INCR) suitable for high-throughput counting.
- Fixed window approach is simple, efficient, and sufficient for most API gateway use cases.
- Separate limits for IP (100 req/min) and authenticated users (200 req/min) prevent abuse at both levels.
- Rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset) provide transparency.

**Security Measures:**
- Limits are enforced before authentication to prevent resource exhaustion.
- Rate limiting is applied to login attempts to prevent brute force attacks.
- Response includes Retry-After header for 429 responses.
- Fail-open behavior: if Redis is unavailable, requests are allowed through.

**Alternatives Considered:**
- **Sliding window (sorted sets)**: More precise but higher Redis memory usage.
- **Token bucket algorithm**: Better for burst traffic but more complex to implement.
- **Nginx-level rate limiting**: Less granular (cannot distinguish authenticated users).

**OWASP Reference:**
- [OWASP Rate Limiting Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)

---

## 5. Security Headers: Defense in Depth

**Decision:** Add comprehensive security headers to all HTTP responses.

**Headers implemented:**
| Header | Value | Purpose |
|--------|-------|---------|
| Content-Security-Policy | restrictive default | Prevent XSS and resource injection |
| X-Content-Type-Options | nosniff | Prevent MIME type sniffing |
| X-Frame-Options | DENY | Prevent clickjacking |
| Strict-Transport-Security | max-age=31536000 | Enforce HTTPS |
| X-XSS-Protection | 0 | Disable legacy XSS filter |
| Referrer-Policy | strict-origin-when-cross-origin | Control referrer information |
| Permissions-Policy | restricted | Limit browser features |
| Cache-Control | no-store | Prevent caching of sensitive data |

**OWASP Reference:**
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

---

## 6. User Enumeration Protection

**Decision:** Use generic error messages for authentication failures.

**Rationale:**
- Returning "Invalid username or password" instead of "User not found" or "Wrong password" prevents attackers from determining valid usernames.
- Registration returns the same error for duplicate email or username ("A user with this email or username already exists").
- Failed login attempts are logged for audit without exposing whether the username existed.

**Alternatives Considered:**
- **Specific error messages**: Rejected because they facilitate user enumeration attacks.
- **Delayed responses**: Could be added but adds complexity for minimal benefit.

**OWASP Reference:**
- [OWASP Authentication Cheat Sheet - User Enumeration](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#prevent-user-enumeration)

---

## 7. Input Validation: Strict Pydantic Schemas

**Decision:** Use Pydantic V2 for strict input validation with custom validators.

**Rationale:**
- All API inputs are validated by Pydantic schemas before reaching business logic.
- Password strength validation ensures: 8+ chars, uppercase, lowercase, digit, special char.
- Username is restricted to alphanumeric and underscore (lowercased automatically).
- Email is validated using IETF-compliant EmailStr.
- Invalid inputs return 422 with structured error details (no sensitive info leaked).

**Alternatives Considered:**
- **Manual validation in controllers**: More error-prone and harder to maintain.
- **JSON Schema validation**: Less Python-native integration.

**OWASP Reference:**
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

---

## 8. Error Handling: No Information Leakage

**Decision:** Return generic error messages for internal errors.

**Rationale:**
- Internal server errors return "An internal error occurred" without stack traces or implementation details.
- Exception details are logged internally with full context for debugging.
- HTTP exception handler provides structured JSON responses with appropriate status codes.
- In production mode, debug information is never exposed.

**Alternatives Considered:**
- **Detailed error responses**: Rejected because they leak system internals.
- **Custom error codes**: Considered but adds complexity without significant security benefit.

**OWASP Reference:**
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

---

## 9. Database Security

**Decision:** Use parameterized queries via SQLAlchemy ORM and connection pooling.

**Rationale:**
- SQLAlchemy ORM provides automatic parameterization, preventing SQL injection.
- Connection pooling limits database connections and prevents resource exhaustion.
- PostgreSQL is configured with:
  - Separate user with minimum required privileges.
  - Password authentication (not trust).
  - Network isolation via Docker network.

**Indices:**
- `users.email` (unique)
- `users.username` (unique)
- `users.id` (primary)
- `refresh_tokens.token_hash` (unique)
- `refresh_tokens.jti` (unique)
- `audit_logs.event_type`
- `audit_logs.created_at`
- `audit_logs.user_id`

**OWASP Reference:**
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

---

## 10. Secret Management

**Decision:** All configuration via environment variables. No secrets in code.

**Rationale:**
- Secrets are loaded at runtime from environment variables via Pydantic Settings.
- `.env.example` provides a template with placeholder values (NEVER real secrets).
- `.env` file is in `.gitignore` and never committed.
- Docker Compose loads secrets from environment variables or `.env` file.
- Production deployments should use a secrets manager (Vault, AWS Secrets Manager, etc.).

**Variables requiring secrets in production:**
- `SECRET_KEY`: Long random string for JWT signing.
- `DATABASE_URL`: Connection string with credentials.
- `REDIS_URL`: Connection string with password if required.

**OWASP Reference:**
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

---

## 11. Logging and Audit

**Decision:** Structured JSON logging with audit trail for security events.

**Rationale:**
- JSON format enables easy ingestion by log aggregation tools (ELK, Grafana Loki, etc.).
- Each log entry includes: timestamp, level, request_id, ip, user_id, endpoint, status_code.
- Security events are logged separately for audit purposes.
- AuditLog model provides a tamper-evident database record of security events.
- `request_id` enables end-to-end tracing across requests.

**Events logged as security events:**
| Event | Severity |
|-------|----------|
| Login successful | info |
| Login failed | warning |
| Registration | info |
| Token refresh | info |
| Logout | info |
| Rate limit exceeded | warning |
| Token revocation | info |
| Suspicious URL pattern | warning |

**OWASP Reference:**
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

## 12. Docker Security

**Decision:** Multi-stage Docker build with non-root user.

**Rationale:**
- Multi-stage build keeps the production image small and free of build tools.
- Application runs as `gateway` user (non-root), not as root.
- HEALTHCHECK ensures the container is actually responding.
- Container-specific networks isolate services from each other.
- Read-only filesystem enforced for data volumes.

**Alternatives Considered:**
- **Single-stage build**: Simpler but results in larger image with unnecessary packages.
- **Root user**: Rejected; containers should never run as root.

**OWASP Reference:**
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

---

## 13. Refresh Token Rotation

**Decision:** Rotate refresh tokens on each use (refresh operation).

**Rationale:**
- Each time a refresh token is used, the old one is revoked and a new one is issued.
- If a stolen refresh token is used, the legitimate user's token will stop working (since the old one is revoked).
- This provides automatic detection of token theft.
- All user tokens can be revoked on demand (logout all sessions).

**Alternatives Considered:**
- **Reusable refresh tokens**: Simpler but less secure.
- **Refresh token with version counter**: More complex to implement.

**OWASP Reference:**
- [OWASP Token Revocation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

## 14. OAuth2 Password Flow Compatibility

**Decision:** Support OAuth2 Password Flow for Swagger UI compatibility.

**Rationale:**
- The `/auth/login` endpoint accepts form-encoded `username` and `password` fields (OAuth2 compatible).
- Swagger UI's "Authorize" button works natively with this flow.
- JSON format is also accepted for programmatic clients.
- Token response follows RFC 6749 format (access_token, refresh_token, token_type, expires_in).

**Alternatives Considered:**
- **OAuth2 Authorization Code Flow**: More secure but requires a client-side redirect flow.
- **Client Credentials Flow**: Appropriate for machine-to-machine but not for user auth.

**OWASP Reference:**
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

---

## Summary of Security Controls

| Control | Implementation |
|---------|---------------|
| Secure password storage | bcrypt (12 rounds) |
| Authentication | JWT with HS256 |
| Token expiry | 15 min access, 7 day refresh |
| Token revocation | Redis blacklist + DB revocation |
| Rate limiting | Redis (IP: 100/min, User: 200/min) |
| Input validation | Pydantic V2 strict schemas |
| Security headers | CSP, HSTS, XFO, etc. |
| Audit logging | Structured JSON + DB AuditLog |
| Error handling | No sensitive info leakage |
| User enumeration prevention | Generic error messages |
| SQL injection prevention | Parameterized queries (SQLAlchemy ORM) |
| Principle of least privilege | Non-root Docker user, separate DB user |
| Secret management | Environment variables only |
| Token rotation | Refresh tokens rotated on use |
| Docker security | Multi-stage build, non-root user |
