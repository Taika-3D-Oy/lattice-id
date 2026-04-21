#!/usr/bin/env python3
"""
Lattice-ID Performance Benchmark Suite

Measures throughput and latency of core OIDC endpoints under load.
Uses only Python stdlib (no external dependencies).

Usage:
    python3 tests/benchmark.py [--base-url URL] [--host HOST] [--concurrency N] [--requests N]

Scenarios:
    1. Discovery       GET  /.well-known/openid-configuration  (cached)
    2. JWKS            GET  /.well-known/jwks.json              (cached)
    3. Registration    POST /register
    4. Full OIDC Flow  authorize → login → token exchange
    5. Token Refresh   POST /token (grant_type=refresh_token)
    6. Userinfo        GET  /userinfo
    7. Concurrent Logins  parallel full OIDC flows
"""

import argparse
import asyncio
import base64
import hashlib
import http.client
import json
import math
import os
import re
import secrets
import statistics
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional


# ── Configuration ────────────────────────────────────────────

@dataclass
class Config:
    base_url: str = "http://localhost:8000"
    host: str = ""
    concurrency: int = 10
    requests_per_scenario: int = 50
    warmup: int = 3


# ── HTTP helpers (stdlib only, thread-safe) ──────────────────

def parse_url(url: str):
    p = urllib.parse.urlparse(url)
    return p.hostname, p.port or (443 if p.scheme == "https" else 80), p.scheme == "https"


def http_request(
    method: str,
    url: str,
    body: Optional[str] = None,
    headers: Optional[dict] = None,
    host_override: str = "",
    follow_redirects: bool = False,
) -> tuple[int, dict, str, dict]:
    """Returns (status, headers_dict, body_text, response_headers)."""
    p = urllib.parse.urlparse(url)
    hostname, port, is_ssl = parse_url(url)
    path = p.path + ("?" + p.query if p.query else "")

    if is_ssl:
        import ssl
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(hostname, port, context=ctx, timeout=15)
    else:
        conn = http.client.HTTPConnection(hostname, port, timeout=15)

    hdrs = {"Host": host_override or hostname}
    if headers:
        hdrs.update(headers)

    try:
        conn.request(method, path, body=body.encode() if body else None, headers=hdrs)
        resp = conn.getresponse()
        resp_body = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}

        if follow_redirects and resp.status in (301, 302, 303, 307, 308):
            location = resp_headers.get("location", "")
            if location:
                # Resolve relative redirects
                if location.startswith("/"):
                    location = f"{p.scheme}://{p.netloc}{location}"
                conn.close()
                return http_request("GET", location, headers=headers,
                                    host_override=host_override, follow_redirects=False)

        return resp.status, resp_headers, resp_body, resp_headers
    finally:
        conn.close()


# ── OIDC helpers ─────────────────────────────────────────────

def pkce_verifier() -> str:
    return secrets.token_urlsafe(32)


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def extract_session_id(html: str) -> Optional[str]:
    m = re.search(r'name="session_id"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


def extract_code_from_location(location: str) -> Optional[str]:
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    codes = qs.get("code", [])
    return codes[0] if codes else None


# ── Benchmark result ─────────────────────────────────────────

@dataclass
class BenchResult:
    name: str
    total_requests: int = 0
    successful: int = 0
    failed: int = 0
    latencies_ms: list = field(default_factory=list)
    start_time: float = 0
    end_time: float = 0
    errors: list = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return self.end_time - self.start_time

    @property
    def rps(self) -> float:
        return self.successful / self.duration_s if self.duration_s > 0 else 0

    @property
    def p50(self) -> float:
        if not self.latencies_ms:
            return 0
        s = sorted(self.latencies_ms)
        return s[len(s) // 2]

    @property
    def p95(self) -> float:
        if not self.latencies_ms:
            return 0
        s = sorted(self.latencies_ms)
        idx = int(len(s) * 0.95)
        return s[min(idx, len(s) - 1)]

    @property
    def p99(self) -> float:
        if not self.latencies_ms:
            return 0
        s = sorted(self.latencies_ms)
        idx = int(len(s) * 0.99)
        return s[min(idx, len(s) - 1)]

    @property
    def avg(self) -> float:
        return statistics.mean(self.latencies_ms) if self.latencies_ms else 0

    @property
    def min_ms(self) -> float:
        return min(self.latencies_ms) if self.latencies_ms else 0

    @property
    def max_ms(self) -> float:
        return max(self.latencies_ms) if self.latencies_ms else 0


# ── Benchmark scenarios ──────────────────────────────────────

class Benchmarker:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.host = cfg.host
        self.results: list[BenchResult] = []
        # Pre-created users for login benchmarks
        self._users: list[dict] = []
        self._client_id = "lid-admin"
        self._redirect_uri = "http://localhost:8090/callback"
        self._tokens: list[dict] = []  # access/refresh tokens for userinfo/refresh tests

    def _url(self, path: str) -> str:
        return f"{self.cfg.base_url}{path}"

    def _req(self, method, path, body=None, headers=None, follow=False):
        return http_request(method, self._url(path), body=body, headers=headers,
                            host_override=self.host, follow_redirects=follow)

    # ── Setup: create test users ─────────────────────────────

    def setup(self):
        """Create test users for login benchmarks."""
        print("\n  Setting up benchmark users...", end="", flush=True)

        # Wait for cluster
        for i in range(60):
            try:
                st, _, _, _ = self._req("GET", "/.well-known/openid-configuration")
                if st == 200:
                    break
            except Exception:
                pass
            time.sleep(1)
        else:
            print(" FAILED (cluster not ready)")
            sys.exit(1)

        n_users = min(self.cfg.requests_per_scenario, 20)
        ts = int(time.time())

        # Register users sequentially to avoid overwhelming Argon2 hashing
        for i in range(n_users):
            email = f"bench-{ts}-{i}@test.local"
            password = f"bench-password-{secrets.token_hex(8)}"
            name = f"Bench User {i}"

            st, _, body, _ = self._req(
                "POST", "/register",
                body=json.dumps({"email": email, "password": password, "name": name}),
                headers={"Content-Type": "application/json"},
            )
            if st == 201:
                self._users.append({"email": email, "password": password, "name": name})
            elif st == 409:
                # Already exists
                self._users.append({"email": email, "password": password, "name": name})
            else:
                if i == 0:
                    print(f"\n  WARNING: first register returned {st}: {body[:200]}")

            if (i + 1) % 20 == 0:
                print(f" {i+1}", end="", flush=True)

        print(f" done ({len(self._users)} users)")

        # Do a few full OIDC flows to pre-populate tokens for refresh/userinfo tests
        print("  Pre-generating tokens...", end="", flush=True)
        for user in self._users[:min(10, len(self._users))]:
            tok, _ = self._do_full_oidc_flow(user)
            if tok:
                self._tokens.append(tok)
        print(f" done ({len(self._tokens)} tokens)")

    def _do_full_oidc_flow(self, user: dict) -> tuple[Optional[dict], str]:
        """Execute a complete OIDC authorization code flow. Returns (tokens_dict, error_msg)."""
        try:
            verifier = pkce_verifier()
            challenge = pkce_challenge(verifier)

            # 1. GET /authorize
            auth_url = (
                f"/authorize?response_type=code&client_id={self._client_id}"
                f"&redirect_uri={urllib.parse.quote(self._redirect_uri, safe='')}"
                f"&scope=openid+email+profile+offline_access"
                f"&state=bench&nonce=bench-{secrets.token_hex(4)}"
                f"&code_challenge={challenge}&code_challenge_method=S256"
            )
            st, hdrs, body, _ = self._req("GET", auth_url)
            if st != 200:
                return (None, f"authorize status={st}")
            session_id = extract_session_id(body)
            if not session_id:
                return (None, "no session_id in authorize response")

            # 2. POST /login
            login_body = urllib.parse.urlencode({
                "session_id": session_id,
                "email": user["email"],
                "password": user["password"],
            })
            st, hdrs, body, _ = self._req(
                "POST", "/login",
                body=login_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            # Should be 302 redirect with code
            location = hdrs.get("location", "")
            code = extract_code_from_location(location)
            if not code:
                return (None, f"login status={st}, no code in location")

            # 3. POST /token
            token_body = urllib.parse.urlencode({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._redirect_uri,
                "client_id": self._client_id,
                "code_verifier": verifier,
            })
            st, _, resp_body, _ = self._req(
                "POST", "/token",
                body=token_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if st != 200:
                return (None, f"token status={st}")

            tokens = json.loads(resp_body)
            return ({
                "access_token": tokens.get("access_token", ""),
                "refresh_token": tokens.get("refresh_token", ""),
                "id_token": tokens.get("id_token", ""),
            }, "")
        except Exception as e:
            return (None, str(e))

    # ── Scenario runners ─────────────────────────────────────

    def bench_discovery(self):
        """GET /.well-known/openid-configuration — cached static JSON."""
        result = BenchResult(name="Discovery")
        n = self.cfg.requests_per_scenario

        # Warmup
        for _ in range(self.cfg.warmup):
            self._req("GET", "/.well-known/openid-configuration")

        result.start_time = time.monotonic()

        def do_one(_):
            t0 = time.monotonic()
            try:
                st, _, _, _ = self._req("GET", "/.well-known/openid-configuration")
                elapsed = (time.monotonic() - t0) * 1000
                if st == 200:
                    return (True, elapsed, None)
                return (False, elapsed, f"status={st}")
            except Exception as e:
                return (False, (time.monotonic() - t0) * 1000, str(e))

        with ThreadPoolExecutor(max_workers=self.cfg.concurrency) as pool:
            for ok, lat, err in pool.map(do_one, range(n)):
                result.total_requests += 1
                if ok:
                    result.successful += 1
                    result.latencies_ms.append(lat)
                else:
                    result.failed += 1
                    if err:
                        result.errors.append(err)

        result.end_time = time.monotonic()
        return result

    def bench_jwks(self):
        """GET /.well-known/jwks.json — cached."""
        result = BenchResult(name="JWKS")
        n = self.cfg.requests_per_scenario

        for _ in range(self.cfg.warmup):
            self._req("GET", "/.well-known/jwks.json")

        result.start_time = time.monotonic()

        def do_one(_):
            t0 = time.monotonic()
            try:
                st, _, _, _ = self._req("GET", "/.well-known/jwks.json")
                elapsed = (time.monotonic() - t0) * 1000
                return (st == 200, elapsed, None if st == 200 else f"status={st}")
            except Exception as e:
                return (False, (time.monotonic() - t0) * 1000, str(e))

        with ThreadPoolExecutor(max_workers=self.cfg.concurrency) as pool:
            for ok, lat, err in pool.map(do_one, range(n)):
                result.total_requests += 1
                if ok:
                    result.successful += 1
                    result.latencies_ms.append(lat)
                else:
                    result.failed += 1

        result.end_time = time.monotonic()
        return result

    def bench_registration(self):
        """POST /register — user creation throughput."""
        result = BenchResult(name="Registration")
        n = self.cfg.requests_per_scenario
        ts = int(time.time())
        # Registration triggers Argon2 hashing (64 MiB each).
        # Cap concurrency to avoid OOM-killing the wasmCloud host.
        max_reg_concurrency = min(self.cfg.concurrency, 3)

        result.start_time = time.monotonic()

        def do_one(i):
            t0 = time.monotonic()
            try:
                email = f"benchreg-{ts}-{i}@test.local"
                body = json.dumps({
                    "email": email,
                    "password": f"bench-pw-{secrets.token_hex(8)}",
                    "name": f"Reg Bench {i}",
                })
                st, _, _, _ = self._req(
                    "POST", "/register",
                    body=body,
                    headers={"Content-Type": "application/json"},
                )
                elapsed = (time.monotonic() - t0) * 1000
                return (st == 201, elapsed, None if st == 201 else f"status={st}")
            except Exception as e:
                return (False, (time.monotonic() - t0) * 1000, str(e))

        with ThreadPoolExecutor(max_workers=max_reg_concurrency) as pool:
            for ok, lat, err in pool.map(do_one, range(n)):
                result.total_requests += 1
                if ok:
                    result.successful += 1
                    result.latencies_ms.append(lat)
                else:
                    result.failed += 1
                    if err and len(result.errors) < 5:
                        result.errors.append(err)

        result.end_time = time.monotonic()
        return result

    def bench_full_oidc_flow(self):
        """Full OIDC authorization code flow (authorize → login → token exchange)."""
        result = BenchResult(name="OIDC Flow")
        n = min(self.cfg.requests_per_scenario, len(self._users))
        if n == 0:
            result.errors.append("no users available")
            return result
        # OIDC flow includes password verify (Argon2). Cap concurrency.
        max_flow_concurrency = min(self.cfg.concurrency, 3)

        result.start_time = time.monotonic()

        def do_one(i):
            user = self._users[i % len(self._users)]
            t0 = time.monotonic()
            try:
                tok, err = self._do_full_oidc_flow(user)
                elapsed = (time.monotonic() - t0) * 1000
                return (tok is not None, elapsed, err if not tok else None)
            except Exception as e:
                return (False, (time.monotonic() - t0) * 1000, str(e))

        with ThreadPoolExecutor(max_workers=max_flow_concurrency) as pool:
            for ok, lat, err in pool.map(do_one, range(n)):
                result.total_requests += 1
                if ok:
                    result.successful += 1
                    result.latencies_ms.append(lat)
                else:
                    result.failed += 1
                    if err and len(result.errors) < 5:
                        result.errors.append(err)

        result.end_time = time.monotonic()
        return result

    def bench_token_refresh(self):
        """POST /token with refresh_token grant."""
        result = BenchResult(name="Token Refresh")
        tokens_with_refresh = [t for t in self._tokens if t.get("refresh_token")]
        n = min(self.cfg.requests_per_scenario, len(tokens_with_refresh))
        if n == 0:
            result.errors.append("no refresh tokens available")
            return result

        result.start_time = time.monotonic()

        def do_one(i):
            tok = tokens_with_refresh[i % len(tokens_with_refresh)]
            t0 = time.monotonic()
            try:
                body = urllib.parse.urlencode({
                    "grant_type": "refresh_token",
                    "refresh_token": tok["refresh_token"],
                    "client_id": self._client_id,
                })
                st, _, resp, _ = self._req(
                    "POST", "/token",
                    body=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                elapsed = (time.monotonic() - t0) * 1000
                if st == 200:
                    # Update the refresh token for next use (rotation)
                    new_tokens = json.loads(resp)
                    if new_tokens.get("refresh_token"):
                        tok["refresh_token"] = new_tokens["refresh_token"]
                    return (True, elapsed, None)
                return (False, elapsed, f"status={st}")
            except Exception as e:
                return (False, (time.monotonic() - t0) * 1000, str(e))

        # Run sequentially per token to avoid rotation conflicts, but parallel across tokens
        with ThreadPoolExecutor(max_workers=min(self.cfg.concurrency, len(tokens_with_refresh))) as pool:
            for ok, lat, err in pool.map(do_one, range(n)):
                result.total_requests += 1
                if ok:
                    result.successful += 1
                    result.latencies_ms.append(lat)
                else:
                    result.failed += 1
                    if err and len(result.errors) < 5:
                        result.errors.append(err)

        result.end_time = time.monotonic()
        return result

    def bench_userinfo(self):
        """GET /userinfo with Bearer token."""
        result = BenchResult(name="Userinfo")
        tokens_with_access = [t for t in self._tokens if t.get("access_token")]
        n = min(self.cfg.requests_per_scenario, len(tokens_with_access) * 10)
        if not tokens_with_access:
            result.errors.append("no access tokens available")
            return result

        result.start_time = time.monotonic()

        def do_one(i):
            tok = tokens_with_access[i % len(tokens_with_access)]
            t0 = time.monotonic()
            try:
                st, _, _, _ = self._req(
                    "GET", "/userinfo",
                    headers={"Authorization": f"Bearer {tok['access_token']}"},
                )
                elapsed = (time.monotonic() - t0) * 1000
                return (st == 200, elapsed, None if st == 200 else f"status={st}")
            except Exception as e:
                return (False, (time.monotonic() - t0) * 1000, str(e))

        with ThreadPoolExecutor(max_workers=self.cfg.concurrency) as pool:
            for ok, lat, err in pool.map(do_one, range(n)):
                result.total_requests += 1
                if ok:
                    result.successful += 1
                    result.latencies_ms.append(lat)
                else:
                    result.failed += 1
                    if err and len(result.errors) < 5:
                        result.errors.append(err)

        result.end_time = time.monotonic()
        return result

    def bench_concurrent_logins(self):
        """Sustained concurrent full OIDC flows at max concurrency."""
        result = BenchResult(name=f"Sustained Load (c={self.cfg.concurrency})")
        n = min(self.cfg.requests_per_scenario, len(self._users) * 2)
        if not self._users:
            result.errors.append("no users")
            return result
        # Login flow includes Argon2. Cap concurrency to avoid OOM.
        max_sustained_concurrency = min(self.cfg.concurrency, 3)

        result.start_time = time.monotonic()

        def do_one(i):
            user = self._users[i % len(self._users)]
            t0 = time.monotonic()
            try:
                tok, err = self._do_full_oidc_flow(user)
                elapsed = (time.monotonic() - t0) * 1000
                return (tok is not None, elapsed, err if not tok else None)
            except Exception as e:
                return (False, (time.monotonic() - t0) * 1000, str(e))

        with ThreadPoolExecutor(max_workers=max_sustained_concurrency) as pool:
            for ok, lat, err in pool.map(do_one, range(n)):
                result.total_requests += 1
                if ok:
                    result.successful += 1
                    result.latencies_ms.append(lat)
                else:
                    result.failed += 1
                    if err and len(result.errors) < 5:
                        result.errors.append(err)

        result.end_time = time.monotonic()
        return result


# ── Report ───────────────────────────────────────────────────

def print_report(results: list[BenchResult], cfg: Config):
    print("\n" + "=" * 80)
    print("  LATTICE-ID PERFORMANCE BENCHMARK RESULTS")
    print("=" * 80)
    print(f"  Target:       {cfg.base_url}")
    print(f"  Concurrency:  {cfg.concurrency}")
    print(f"  Requests/scenario: {cfg.requests_per_scenario}")
    print()

    # Header
    fmt = "  {:<28s} {:>6s} {:>6s} {:>8s} {:>8s} {:>8s} {:>8s} {:>8s}"
    print(fmt.format("Scenario", "OK", "Fail", "RPS", "Avg ms", "P50 ms", "P95 ms", "P99 ms"))
    print("  " + "-" * 76)

    for r in results:
        if r.total_requests == 0:
            print(f"  {r.name:<28s} {'SKIPPED':>6s}   {'; '.join(r.errors[:2])}")
            continue

        fmt_row = "  {:<28s} {:>6d} {:>6d} {:>8.1f} {:>8.1f} {:>8.1f} {:>8.1f} {:>8.1f}"
        print(fmt_row.format(
            r.name, r.successful, r.failed,
            r.rps, r.avg, r.p50, r.p95, r.p99,
        ))

    print("  " + "-" * 76)
    print()

    # Detailed view for scenarios with errors
    for r in results:
        if r.errors:
            print(f"  {r.name} errors (first {min(3, len(r.errors))}):")
            for e in r.errors[:3]:
                print(f"    - {e[:120]}")
            print()

    # Summary stats
    total_ok = sum(r.successful for r in results)
    total_fail = sum(r.failed for r in results)
    total_reqs = sum(r.total_requests for r in results)
    total_dur = sum(r.duration_s for r in results)

    print(f"  Total: {total_reqs} requests, {total_ok} ok, {total_fail} failed")
    print(f"  Wall time: {total_dur:.1f}s")

    if any(r.latencies_ms for r in results):
        all_lat = []
        for r in results:
            all_lat.extend(r.latencies_ms)
        if all_lat:
            print(f"  Overall latency: min={min(all_lat):.1f}ms  avg={statistics.mean(all_lat):.1f}ms  max={max(all_lat):.1f}ms")

    print("=" * 80)
    print()


# ── Main ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Lattice-ID Performance Benchmark")
    parser.add_argument("--base-url", default=os.environ.get("BASE_URL", "http://localhost:8000"),
                        help="Base URL of the lattice-id instance")
    parser.add_argument("--host", default=os.environ.get("HOST", ""),
                        help="Host header override (e.g., eu.lid.internal)")
    parser.add_argument("--concurrency", "-c", type=int, default=10,
                        help="Number of concurrent workers (default: 10)")
    parser.add_argument("--requests", "-n", type=int, default=100,
                        help="Requests per scenario (default: 100)")
    parser.add_argument("--warmup", type=int, default=5,
                        help="Warmup requests before each scenario")
    parser.add_argument("--scenarios", nargs="+",
                        choices=["discovery", "jwks", "register", "oidc", "refresh", "userinfo", "sustained", "all"],
                        default=["all"], help="Which scenarios to run")
    args = parser.parse_args()

    cfg = Config(
        base_url=args.base_url,
        host=args.host,
        concurrency=args.concurrency,
        requests_per_scenario=args.requests,
        warmup=args.warmup,
    )

    bench = Benchmarker(cfg)

    print("\n" + "=" * 80)
    print("  LATTICE-ID PERFORMANCE BENCHMARK")
    print("=" * 80)
    print(f"  Target:       {cfg.base_url}")
    if cfg.host:
        print(f"  Host header:  {cfg.host}")
    print(f"  Concurrency:  {cfg.concurrency}")
    print(f"  Requests:     {cfg.requests_per_scenario} per scenario")

    run_all = "all" in args.scenarios
    scenarios = args.scenarios

    # Setup: register users (needed for login/oidc/refresh/userinfo)
    needs_users = run_all or any(s in scenarios for s in ["oidc", "refresh", "userinfo", "sustained", "register"])
    if needs_users:
        bench.setup()

    results = []

    def run_scenario(name, fn):
        print(f"\n  Running: {name}...", flush=True)
        result = fn()
        results.append(result)
        if result.total_requests > 0:
            print(f"    {result.successful}/{result.total_requests} ok, "
                  f"{result.rps:.1f} rps, p50={result.p50:.1f}ms, p95={result.p95:.1f}ms")
        else:
            print(f"    SKIPPED: {'; '.join(result.errors[:2])}")

    if run_all or "discovery" in scenarios:
        run_scenario("Discovery (GET /.well-known/openid-configuration)", bench.bench_discovery)

    if run_all or "jwks" in scenarios:
        run_scenario("JWKS (GET /.well-known/jwks.json)", bench.bench_jwks)

    if run_all or "register" in scenarios:
        run_scenario("Registration (POST /register)", bench.bench_registration)

    if run_all or "oidc" in scenarios:
        run_scenario("Full OIDC Flow (authorize → login → token)", bench.bench_full_oidc_flow)

    if run_all or "refresh" in scenarios:
        run_scenario("Token Refresh (POST /token)", bench.bench_token_refresh)

    if run_all or "userinfo" in scenarios:
        run_scenario("Userinfo (GET /userinfo)", bench.bench_userinfo)

    if run_all or "sustained" in scenarios:
        run_scenario(f"Sustained Load (c={cfg.concurrency})", bench.bench_concurrent_logins)

    print_report(results, cfg)


if __name__ == "__main__":
    main()
