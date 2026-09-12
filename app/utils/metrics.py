"""
Centralized Prometheus metrics for the API Gateway.

All counters, histograms, and gauges are defined here so they are
created exactly once on the default registry and shared across the
application (middleware, services, rate limiter).

Disabled by setting PROMETHEUS_ENABLED=false, but metrics are still
safe to instantiate (they are simply not exposed via /metrics).
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# --- HTTP ---
http_requests_total = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)
http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# --- Authentication events ---
auth_login_success_total = Counter(
    "auth_login_success_total",
    "Total successful logins",
)
auth_login_failure_total = Counter(
    "auth_login_failure_total",
    "Total failed logins",
)
auth_register_total = Counter(
    "auth_register_total",
    "Total user registrations",
)

# --- Rate limiting ---
rate_limit_blocked_total = Counter(
    "rate_limit_blocked_total",
    "Total requests blocked by rate limiter",
)

# --- Connections ---
active_connections = Gauge(
    "active_connections",
    "Number of active connections",
)