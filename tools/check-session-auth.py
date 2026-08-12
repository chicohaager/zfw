#!/usr/bin/env python3
"""Prove ZFW's session auth against a running ZimaOS host — both directions.

Why this exists: ZFW verifies the ZimaOS session token itself (the gateway
proxies module routes without authenticating them) and pins the token's `iss`
claim so a refresh token cannot be replayed as a firewall session. That claim
is a value ZimaOS mints, and ZimaOS has already renamed it once — `casaos`
through v1.7.0-beta1, `zimaos` from v1.7.1-beta1. When it changed, every ZFW
tab answered 401 and the only visible trace was in the browser console.

So after every ZimaOS update, run this. It checks the half that must pass AND
the half that must fail — a check that only proves acceptance would stay green
if the issuer scoping were dropped altogether.

    python3 tools/check-session-auth.py <host> --user <name> --password-file <f>

The password is read from a file and never printed; neither is any token.
Exit 0 = both directions correct, exit 1 = something to fix.
"""
import argparse
import base64
import json
import sys
import urllib.error
import urllib.request

TIMEOUT = 10


def post(host, path, obj):
    req = urllib.request.Request(
        f"http://{host}{path}",
        data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read())


def claims(token):
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def call_zfw(host, authorization=None):
    """Return (status, body) for GET /v2/zfw/api/status through the gateway —
    the same path and port the browser uses, not the daemon's loopback port."""
    req = urllib.request.Request(f"http://{host}/v2/zfw/api/status")
    if authorization:
        req.add_header("Authorization", authorization)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read()[:200]
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:200]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host", help="ZimaOS host, e.g. 192.168.1.143")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file", required=True,
                    help="file holding the password (mode 0600); never printed")
    args = ap.parse_args()

    with open(args.password_file) as fh:
        password = fh.read().strip()

    try:
        body = post(args.host, "/v1/users/login",
                    {"username": args.user, "password": password})
    except urllib.error.HTTPError as e:
        print(f"login failed: HTTP {e.code}", file=sys.stderr)
        return 1
    tokens = body["data"]["token"]
    access, refresh = tokens["access_token"], tokens["refresh_token"]

    print(f"host {args.host}: access iss={claims(access)['iss']!r}, "
          f"refresh iss={claims(refresh)['iss']!r}")

    failures = []

    status, resp = call_zfw(args.host, "Bearer " + access)
    ok = status == 200
    print(f"  access token accepted            HTTP {status}  {'OK' if ok else 'FAIL'}")
    if not ok:
        failures.append(f"a genuine session token was refused: {resp.decode(errors='replace').strip()}")

    # The negative half. Each of these must be 401 — if the issuer check were
    # widened to "any issuer", the first one would silently start passing.
    for label, header in (
        ("refresh token refused", "Bearer " + refresh),
        ("no Authorization refused", None),
        ("tampered signature refused", "Bearer " + access[:-4] + "AAAA"),
    ):
        status, resp = call_zfw(args.host, header)
        ok = status == 401
        print(f"  {label:<32} HTTP {status}  {'OK' if ok else 'FAIL'}")
        if not ok:
            failures.append(f"{label}: got HTTP {status}")

    if failures:
        print("\nFAIL:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nPASS — session auth accepts the real token and refuses the rest.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
