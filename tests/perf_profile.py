#!/usr/bin/env python3
"""Profile each step of an OIDC flow and report latencies."""
import time
import re
import hashlib
import base64
import os
import secrets
from urllib.parse import urlparse, parse_qs
import subprocess
import sys

BASE = os.environ.get("BASE_URL", "http://localhost:8000")

def curl_time(method, url, headers=None, data=None, follow=False):
    """Run curl and return (status, body, elapsed, resp_headers)."""
    cmd = ["curl", "-s", "-o", "/tmp/pt_body", "-D", "/tmp/pt_hdr", "-w", "%{http_code}"]
    if not follow:
        cmd.append("--max-redirs")
        cmd.append("0")
    if method == "POST":
        cmd += ["-X", "POST"]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if data:
        cmd += ["-d", data]
    cmd.append(url)
    
    t0 = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    elapsed = time.time() - t0
    
    status = result.stdout.strip()
    body = open("/tmp/pt_body", "r").read() if os.path.exists("/tmp/pt_body") else ""
    hdrs = open("/tmp/pt_hdr", "r").read() if os.path.exists("/tmp/pt_hdr") else ""
    return status, body, elapsed, hdrs


def pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


def main():
    ts = int(time.time())
    email = f"perf.{ts}.{os.getpid()}@test.com"
    password = "testpass123"
    
    print(f"=== OIDC Flow Performance Profile ===")
    print(f"Email: {email}")
    print()
    
    results = []
    
    # Step 1: Register
    status, body, elapsed, _ = curl_time("POST", f"{BASE}/register",
        headers={"content-type": "application/json"},
        data=f'{{"email":"{email}","password":"{password}","name":"Perf"}}')
    results.append(("Register", status, elapsed))
    print(f"  Register:       HTTP {status} | {elapsed:.3f}s")
    
    # Step 2: PKCE + Authorize
    verifier, challenge = pkce()
    status, body, elapsed, _ = curl_time("GET",
        f"{BASE}/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&scope=openid+email+profile&state=test&nonce=n1&code_challenge={challenge}&code_challenge_method=S256")
    results.append(("Authorize", status, elapsed))
    print(f"  Authorize:      HTTP {status} | {elapsed:.3f}s")
    
    m = re.search(r'name="session_id"\s+value="([^"]+)"', body)
    if not m:
        print(f"  ERROR: no session_id in authorize response. Body: {body[:200]}")
        sys.exit(1)
    sid = m.group(1)
    
    # Step 3: Login (password verification)
    print(f"  Login:          ... (measuring)", end="", flush=True)
    status, body, elapsed, hdrs = curl_time("POST", f"{BASE}/login",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data=f"session_id={sid}&email={email}&password={password}")
    results.append(("Login (pw verify)", status, elapsed))
    print(f"\r  Login (verify): HTTP {status} | {elapsed:.3f}s")
    
    # Extract code from Location header
    location = ""
    for line in hdrs.split("\n"):
        if line.lower().startswith("location:"):
            location = line.split(":", 1)[1].strip()
            break
    
    code = "NONE"
    if location:
        qs = parse_qs(urlparse(location).query)
        code = qs.get("code", ["NONE"])[0]
    
    if code == "NONE":
        print(f"  ERROR: no code in redirect. Status={status}, body={body[:200]}")
        # Continue anyway to measure token exchange with invalid code
    
    # Step 4: Token exchange (JWT signing)
    print(f"  Token:          ... (measuring)", end="", flush=True)
    status, body, elapsed, _ = curl_time("POST", f"{BASE}/token",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data=f"grant_type=authorization_code&code={code}&code_verifier={verifier}&client_id=lid-admin&redirect_uri=http://localhost:8090/callback")
    results.append(("Token (JWT sign)", status, elapsed))
    print(f"\r  Token (sign):   HTTP {status} | {elapsed:.3f}s")
    
    # Try to extract access_token
    import json
    try:
        token_data = json.loads(body)
        access_token = token_data.get("access_token", "")
    except:
        access_token = ""
        print(f"  Token body: {body[:200]}")
    
    # Step 5: Userinfo
    if access_token:
        status, body, elapsed, _ = curl_time("GET", f"{BASE}/userinfo",
            headers={"Authorization": f"Bearer {access_token}"})
        results.append(("Userinfo", status, elapsed))
        print(f"  Userinfo:       HTTP {status} | {elapsed:.3f}s")
    
    # === Second run (warm) ===
    print()
    print("=== Second Login (warm cache) ===")
    
    verifier2, challenge2 = pkce()
    status, body, elapsed, _ = curl_time("GET",
        f"{BASE}/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&scope=openid+email+profile&state=t2&nonce=n2&code_challenge={challenge2}&code_challenge_method=S256")
    results.append(("Authorize (2nd)", status, elapsed))
    print(f"  Authorize:      HTTP {status} | {elapsed:.3f}s")
    
    m = re.search(r'name="session_id"\s+value="([^"]+)"', body)
    if m:
        sid2 = m.group(1)
        print(f"  Login (2nd):    ... (measuring)", end="", flush=True)
        status, body, elapsed, hdrs = curl_time("POST", f"{BASE}/login",
            headers={"content-type": "application/x-www-form-urlencoded"},
            data=f"session_id={sid2}&email={email}&password={password}")
        results.append(("Login 2nd (pw)", status, elapsed))
        print(f"\r  Login (2nd):    HTTP {status} | {elapsed:.3f}s")
        
        location = ""
        for line in hdrs.split("\n"):
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                break
        code2 = "NONE"
        if location:
            qs = parse_qs(urlparse(location).query)
            code2 = qs.get("code", ["NONE"])[0]
        
        if code2 != "NONE":
            print(f"  Token (2nd):    ... (measuring)", end="", flush=True)
            status, body, elapsed, _ = curl_time("POST", f"{BASE}/token",
                headers={"content-type": "application/x-www-form-urlencoded"},
                data=f"grant_type=authorization_code&code={code2}&code_verifier={verifier2}&client_id=lid-admin&redirect_uri=http://localhost:8090/callback")
            results.append(("Token 2nd (JWT)", status, elapsed))
            print(f"\r  Token (2nd):    HTTP {status} | {elapsed:.3f}s")
    
    # Summary
    print()
    print("=== SUMMARY ===")
    total = sum(r[2] for r in results)
    for name, status, elapsed in results:
        pct = (elapsed / total) * 100 if total > 0 else 0
        bar = "#" * int(pct / 2)
        print(f"  {name:20s}  HTTP {status}  {elapsed:7.3f}s  {pct:5.1f}%  {bar}")
    print(f"  {'TOTAL':20s}         {total:7.3f}s")


if __name__ == "__main__":
    main()
