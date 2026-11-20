"""x402lint — does an x402 paid endpoint actually publish a usable offer?

Probes a URL with GET + OPTIONS and checks the 402 offer for protocol shape,
address validity, browser reachability, and header/body agreement. Pure checks
are separated from the network probe so every rule has a fixture.

Grounded in a real production defect: payclient was unwireable from a browser
because OPTIONS /paid/swapcheck returned 501, so no wallet could preflight the
PAYMENT-SIGNATURE header. Rule 13 exists because of that.
"""
import base64
import binascii
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HEADER = "payment-required"
ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
KNOWN_NETWORKS = {
    "eip155:8453", "eip155:1", "eip155:84532", "eip155:11155111",
    "base", "base-sepolia", "ethereum", "ethereum-sepolia", "solana",
}
UA = "x402lint/1.0 (+https://seed-0x01.konnektr.io; autonomous AI agent)"


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def decode_offer(raw):
    """Decode a base64url PAYMENT-REQUIRED header into a dict, or None."""
    if not raw:
        return None
    s = str(raw).strip().strip('"')
    if not s:
        return None
    try:
        pad = "=" * (-len(s) % 4)
        data = base64.urlsafe_b64decode(s + pad)
        obj = json.loads(data.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except (binascii.Error, ValueError, UnicodeDecodeError, TypeError):
        return None


def encode_offer(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _lower(headers):
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _has(h, name, token):
    return token.lower() in h.get(name, "").lower()


def _norm_url(u):
    if not u:
        return ""
    p = urllib.parse.urlsplit(u)
    return (p.scheme.lower() + "://" + p.netloc.lower() + p.path.rstrip("/")).lower()


def checks(status, headers, body, opt_status=None, opt_headers=None,
           requested_url=None, require_ai_disclosure=False):
    """Return (verdict, checks). verdict in PASS/WARN/FAIL.

    status:int, headers:dict, body:str|bytes, opt_status:int|None,
    opt_headers:dict|None, requested_url:str|None.
    """
    h = _lower(headers)
    oh = _lower(opt_headers)
    result = []

    def add(name, ok, detail, level="error"):
        result.append({"name": name, "ok": bool(ok), "detail": detail, "level": level})

    # 1. status
    add("01 status is 402", status == 402,
        "got %s (x402 v2 expects 402 Payment Required)" % status)

    # 2-3. header presence and decodability
    raw = h.get(HEADER, "")
    add("02 PAYMENT-REQUIRED header present", bool(raw),
        "header found" if raw else "no %s header — a client cannot discover terms" % HEADER)
    offer = decode_offer(raw)
    add("03 offer header decodes to JSON object", offer is not None,
        "decoded x402Version=%s" % (offer.get("x402Version") if offer else "n/a"))

    if offer is None:
        offer = {}

    # 4. version
    ver = offer.get("x402Version")
    add("04 x402Version is 1 or 2", ver in (1, 2), "got %r" % ver)

    # 5. accepts
    accepts = offer.get("accepts")
    accepts = accepts if isinstance(accepts, list) else []
    add("05 accepts is a non-empty list", len(accepts) > 0,
        "%d payment requirement(s)" % len(accepts))

    for i, a in enumerate(accepts):
        a = a if isinstance(a, dict) else {}
        pre = "06.%d accept[%d]" % (i, i)
        add(pre + " scheme", a.get("scheme") == "exact",
            "scheme=%r (expected 'exact')" % a.get("scheme"))
        add(pre + " network", a.get("network") in KNOWN_NETWORKS,
            "network=%r" % a.get("network"))
        for field in ("asset", "payTo"):
            val = a.get(field)
            add(pre + " " + field, bool(isinstance(val, str) and ADDR.match(val)),
                "%s=%r" % (field, val))
        amt = a.get("amount")
        amt_ok = isinstance(amt, str) and amt.isdigit() and int(amt) > 0
        add(pre + " amount", amt_ok,
            "amount=%r (need positive integer STRING, atomic units)" % amt)
        t = a.get("maxTimeoutSeconds")
        add(pre + " maxTimeoutSeconds", isinstance(t, int) and t > 0,
            "maxTimeoutSeconds=%r" % t)

    # 10. resource
    res = offer.get("resource")
    res = res if isinstance(res, dict) else {}
    ru = res.get("url", "")
    parsed = urllib.parse.urlsplit(ru) if isinstance(ru, str) else urllib.parse.urlsplit("")
    add("10 resource.url is absolute http(s)", parsed.scheme in ("http", "https") and bool(parsed.netloc),
        "resource.url=%r" % ru)
    if requested_url and ru:
        add("11 resource.url matches requested URL",
            _norm_url(ru) == _norm_url(requested_url),
            "advertised %s; requested %s" % (ru, requested_url), level="warn")
    else:
        add("11 resource.url matches requested URL", True, "not checked (no requested URL)")

    # 12. header vs body offer agreement
    body_offer = None
    if body:
        try:
            decoded = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
            if isinstance(decoded, dict):
                body_offer = decoded.get("offer", decoded.get("accepts") and decoded)
        except (ValueError, TypeError):
            pass
    if body_offer is None:
        add("12 body offer agrees with header", True,
            "body carries no duplicate offer — header is authoritative")
    else:
        same = json.dumps(body_offer, sort_keys=True, separators=(",", ":")) == \
               json.dumps(offer, sort_keys=True, separators=(",", ":"))
        add("12 body offer agrees with header", same,
            "header and body offer are byte-equal" if same else
            "MISMATCH: body offer differs from PAYMENT-REQUIRED header")

    # 13-14. CORS on the 402 response
    add("13 CORS allow-origin on offer", bool(h.get("access-control-allow-origin")),
        "ACAO=%r" % h.get("access-control-allow-origin"))
    add("14 PAYMENT-REQUIRED exposed to JS", _has(h, "access-control-expose-headers", HEADER),
        "expose=%r" % h.get("access-control-expose-headers"))

    # 15. no-store
    add("15 offer marked no-store", _has(h, "cache-control", "no-store"),
        "cache-control=%r" % h.get("cache-control"))

    # 16-17. browser preflight (the real defect this tool was built to catch)
    if opt_status is None:
        add("16 OPTIONS preflight succeeds", False, "no preflight response captured", level="warn")
        add("17 preflight allows PAYMENT-SIGNATURE", False, "no preflight response captured", level="warn")
    else:
        add("16 OPTIONS preflight succeeds", opt_status in (200, 204),
            "OPTIONS returned %s (a 501 makes every browser wallet fail before it can pay)" % opt_status)
        add("17 preflight allows PAYMENT-SIGNATURE",
            _has(oh, "access-control-allow-headers", "payment-signature") or
            _has(oh, "access-control-allow-headers", "x-payment"),
            "allow-headers=%r" % oh.get("access-control-allow-headers"))

    # 18. AI disclosure ( CONSTITUTION §2 ) — advisory, not a protocol gate
    if require_ai_disclosure:
        desc = str(res.get("description", ""))
        disclosed = ("autonomous" in desc.lower()) or ("ai agent" in desc.lower())
        add("18 AI authorship disclosed in offer", disclosed,
            "resource.description discloses autonomous authorship" if disclosed else
            "no 'autonomous'/'AI agent' in resource.description", level="warn")

    hard_fail = any(c["level"] == "error" and not c["ok"] for c in result)
    soft_fail = any(c["level"] == "warn" and not c["ok"] for c in result)
    verdict = "FAIL" if hard_fail else ("WARN" if soft_fail else "PASS")
    return verdict, result


def probe(url, timeout=20):
    """GET + OPTIONS a URL, return a report dict. 402 is an expected HTTPError."""
    req = urllib.request.Request(url, headers={
        "Accept": "application/json", "Origin": "https://example.com", "User-Agent": UA,
    })
    status, headers, body = None, {}, b""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, headers, body = r.status, dict(r.headers.items()), r.read()
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, dict(e.headers.items()), e.read()
    except Exception as e:
        return {"url": url, "read_at": now_iso(), "verdict": "FAIL",
                "error": "%s: %s" % (type(e).__name__, e), "checks": []}

    opt_req = urllib.request.Request(url, method="OPTIONS", headers={
        "Origin": "https://example.com", "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "PAYMENT-SIGNATURE", "User-Agent": UA,
    })
    opt_status, opt_headers = None, {}
    try:
        with urllib.request.urlopen(opt_req, timeout=timeout) as r:
            opt_status, opt_headers = r.status, dict(r.headers.items())
    except urllib.error.HTTPError as e:
        opt_status, opt_headers = e.code, dict(e.headers.items())
    except Exception:
        pass

    verdict, result = checks(status, headers, body, opt_status, opt_headers,
                             requested_url=url, require_ai_disclosure=True)
    return {"url": url, "read_at": now_iso(), "verdict": verdict,
            "status": status, "opt_status": opt_status, "body_bytes": len(body),
            "checks": result}


# ---- fixtures -------------------------------------------------------------

def _valid_offer():
    return {
        "x402Version": 2,
        "resource": {"url": "https://example.com/paid/report",
                     "description": "A fresh signed report by an autonomous AI agent.",
                     "mimeType": "application/json"},
        "accepts": [{"scheme": "exact", "network": "eip155:8453",
                     "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                     "amount": "1000000",
                     "payTo": "0x663952620CEeF96C9Ebe9B5002Cc5910A7CD8FFd",
                     "maxTimeoutSeconds": 300}],
    }


def _ctx():
    offer = _valid_offer()
    body = json.dumps({"x402Message": "Payment required.", "offer": offer})
    return {
        "status": 402,
        "headers": {"payment-required": encode_offer(offer),
                    "access-control-allow-origin": "*",
                    "access-control-expose-headers": "PAYMENT-REQUIRED",
                    "cache-control": "no-store"},
        "body": body, "opt_status": 204,
        "opt_headers": {"access-control-allow-headers": "Content-Type, PAYMENT-SIGNATURE, X-PAYMENT"},
        "requested_url": "https://example.com/paid/report",
        "require_ai_disclosure": True,
    }


def fixtures():
    """Yield (name, ctx, expected_verdict, expected_failed_check_substring)."""
    out = []

    def add(name, ctx, verdict, needle=None):
        out.append((name, ctx, verdict, needle))

    add("valid offer", _ctx(), "PASS")

    c = _ctx(); c["status"] = 200
    add("wrong status 200", c, "FAIL", "01 status")

    c = _ctx(); c["headers"].pop("payment-required")
    add("missing header", c, "FAIL", "02 PAYMENT-REQUIRED")

    c = _ctx(); c["headers"]["payment-required"] = "!!!not-base64!!!"
    add("undecodable header", c, "FAIL", "03 offer header decodes")

    c = _ctx(); o = _valid_offer(); o["x402Version"] = 9
    c["headers"]["payment-required"] = encode_offer(o)
    c["body"] = json.dumps({"offer": o})
    add("unknown version", c, "FAIL", "04 x402Version")

    c = _ctx(); o = _valid_offer(); o["accepts"] = []
    c["headers"]["payment-required"] = encode_offer(o)
    c["body"] = json.dumps({"offer": o})
    add("empty accepts", c, "FAIL", "05 accepts")

    c = _ctx(); o = _valid_offer(); o["accepts"][0]["payTo"] = "0xdeadbeef"
    c["headers"]["payment-required"] = encode_offer(o)
    c["body"] = json.dumps({"offer": o})
    add("invalid payTo", c, "FAIL", "payTo")

    c = _ctx(); o = _valid_offer(); o["accepts"][0]["amount"] = "0"
    c["headers"]["payment-required"] = encode_offer(o)
    c["body"] = json.dumps({"offer": o})
    add("zero amount", c, "FAIL", "amount")

    c = _ctx(); o = _valid_offer(); o["accepts"][0]["amount"] = 1000000
    c["headers"]["payment-required"] = encode_offer(o)
    c["body"] = json.dumps({"offer": o})
    add("amount as int not string", c, "FAIL", "amount")

    c = _ctx(); o = _valid_offer(); o["accepts"][0]["network"] = "eip155:999999"
    c["headers"]["payment-required"] = encode_offer(o)
    c["body"] = json.dumps({"offer": o})
    add("unknown network", c, "FAIL", "network")

    c = _ctx(); o = _valid_offer()
    c["body"] = json.dumps({"offer": {**o, "accepts": [{**o["accepts"][0], "amount": "2"}]}})
    add("header/body mismatch", c, "FAIL", "12 body offer agrees")

    c = _ctx(); c["headers"].pop("access-control-allow-origin")
    add("no CORS", c, "FAIL", "13 CORS")

    c = _ctx(); c["headers"].pop("access-control-expose-headers")
    add("header not exposed to JS", c, "FAIL", "14 PAYMENT-REQUIRED exposed")

    c = _ctx(); c["headers"].pop("cache-control")
    add("cacheable offer", c, "FAIL", "15 offer marked no-store")

    c = _ctx(); c["opt_status"] = 501
    add("OPTIONS 501 (real bug)", c, "FAIL", "16 OPTIONS")

    c = _ctx(); c["opt_headers"] = {"access-control-allow-headers": "Content-Type"}
    add("preflight blocks payment header", c, "FAIL", "17 preflight allows")

    c = _ctx(); c["requested_url"] = "https://example.com/somewhere-else"
    add("resource URL drift", c, "WARN", "11 resource.url matches")

    c = _ctx(); o = _valid_offer(); o["resource"]["description"] = "A signed report."
    c["headers"]["payment-required"] = encode_offer(o)
    c["body"] = json.dumps({"offer": o})
    add("no AI disclosure", c, "WARN", "18 AI authorship")

    c = _ctx(); c["body"] = json.dumps({"x402Message": "pay up", "hint": "header is authoritative"})
    add("header-only offer (no body copy)", c, "PASS")
    return out


def selftest():
    rows = []
    for name, ctx, expected, needle in fixtures():
        verdict, result = checks(**ctx)
        ok = verdict == expected
        if needle:
            failed = [r["name"] for r in result if not r["ok"]]
            ok = ok and any(needle in f for f in failed)
        rows.append({"name": name, "expected": expected, "got": verdict,
                     "needle": needle or "", "ok": ok})
    return rows


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        rows = selftest()
        for r in rows:
            print(("PASS" if r["ok"] else "FAIL"), "|", r["name"],
                  "| expected", r["expected"], "got", r["got"])
        print("%d/%d fixtures pass" % (sum(r["ok"] for r in rows), len(rows)))
        sys.exit(0 if all(r["ok"] for r in rows) else 3)
    if len(sys.argv) != 2:
        print("usage: lint.py <url> | --selftest", file=sys.stderr)
        sys.exit(2)
    report = probe(sys.argv[1])
    print("VERDICT %s — %s (read %s)" % (report["verdict"], report["url"], report["read_at"]))
    if report.get("error"):
        print("error:", report["error"])
    for c in report.get("checks", []):
        print("  %-4s %-42s %s" % ("PASS" if c["ok"] else "FAIL", c["name"], c["detail"]))
    sys.exit(0 if report["verdict"] != "FAIL" else 1)
