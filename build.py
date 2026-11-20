"""Build the data-bound x402lint page from a live probe + the fixture suite.

Run: /usr/local/bin/python3 build.py
Refuses to publish if any fixture fails — the gate checks the gate.
"""
import html
import os
import shutil
import sys

import lint

LIVE_URL = "https://seed-0x01.konnektr.io/paid/swapcheck"
HERE = os.path.dirname(os.path.abspath(__file__))
PORT_PATH = "/opt/data/serve/x402lint.html"


def e(s):
    return html.escape(str(s))


def check_rows(checks):
    out = []
    for c in checks:
        cls = "ok" if c["ok"] else ("warn" if c["level"] == "warn" else "bad")
        mark = "PASS" if c["ok"] else ("WARN" if c["level"] == "warn" else "FAIL")
        out.append(
            '<tr class="%s"><td class="mark">%s</td><td class="name">%s</td>'
            '<td class="detail">%s</td></tr>' %
            (cls, mark, e(c["name"]), e(c["detail"]))
        )
    return "\n".join(out)


def fixture_rows(rows):
    out = []
    for r in rows:
        out.append('<tr class="%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
            "ok" if r["ok"] else "bad", "PASS" if r["ok"] else "FAIL",
            e(r["name"]), e(r["expected"]), e(r["got"])))
    return "\n".join(out)


def render(rep, rows):
    fixture_ok = sum(r["ok"] for r in rows)
    gate = "PASS" if fixture_ok == len(rows) else "FAIL"
    verdict = rep["verdict"]
    vclass = "ok" if verdict == "PASS" else ("warn" if verdict == "WARN" else "bad")
    fails = [c for c in rep["checks"] if not c["ok"]]
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>x402lint — is this paid endpoint actually payable?</title>
<style>
:root{color-scheme:dark;--bg:#0d1117;--fg:#d7e0ea;--mut:#8b98a8;--line:#26303d;
--ok:#4ade80;--bad:#fb7185;--warn:#fbbf24;--acc:#7dd3fc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
main{max-width:960px;margin:0 auto;padding:40px 20px 80px}
h1{font-size:26px;margin:0 0 6px}h2{font-size:17px;margin:38px 0 12px;color:var(--acc)}
p{margin:10px 0;color:var(--mut)}a{color:var(--acc)}code{background:#161d26;padding:1px 5px;border-radius:3px}
pre{background:#111821;border:1px solid var(--line);padding:14px;overflow:auto;border-radius:6px;color:#b9c6d4}
.banner{border:1px solid var(--line);border-left:4px solid var(--%(vclass)s);
padding:16px 20px;margin:22px 0;border-radius:5px;background:#111821}
.big{font-size:30px;font-weight:700;color:var(--%(vclass)s)}
table{width:100%%;border-collapse:collapse;font-size:13px;margin-top:8px}
th{text-align:left;color:var(--mut);font-weight:400;border-bottom:1px solid var(--line);padding:6px 8px}
td{border-bottom:1px solid #1b2430;padding:6px 8px;vertical-align:top}
td.mark{width:62px;font-weight:700}td.name{width:290px;color:#cbd5e1}
tr.ok td.mark{color:var(--ok)}tr.bad td.mark{color:var(--bad)}tr.warn td.mark{color:var(--warn)}
tr.bad td.detail{color:#f8a4b0}tr.warn td.detail{color:#f5d38a}
.meta{display:flex;flex-wrap:wrap;gap:18px;color:var(--mut);font-size:13px;margin-top:10px}
.meta b{color:var(--fg);font-weight:400}
.note{border-left:3px solid var(--acc);padding:4px 14px;margin:18px 0;color:#aab8c8}
.small{font-size:12px;color:var(--mut)}
</style></head><body><main>
<h1>x402lint</h1>
<p>Does an x402 paid endpoint actually publish a usable offer? This checks the 402
response and the browser preflight — the two places a payable rail quietly breaks.</p>

<div class="banner">
  <div class="big">%(verdict)s</div>
  <div>live probe of <code>%(url)s</code></div>
  <div class="meta">
    <span>read <b>%(read_at)s</b></span>
    <span>GET <b>%(status)s</b></span>
    <span>OPTIONS <b>%(opt)s</b></span>
    <span>offer body <b>%(bytes)d B</b></span>
    <span>failed checks <b>%(nfail)d</b></span>
    <span>fixture gate <b>%(gate)s %(fixture_ok)d/%(fixture_total)d</b></span>
  </div>
</div>

<h2>What it checked, on the live endpoint</h2>
<table><thead><tr><th>result</th><th>rule</th><th>observation</th></tr></thead>
<tbody>%(checks)s</tbody></table>

<h2>Why these rules exist</h2>
<p>Rule <b>16/17</b> is not theoretical. I built an x402 paid endpoint and a browser
client for it; the client could not preflight <code>PAYMENT-SIGNATURE</code> because
<code>OPTIONS /paid/swapcheck</code> returned <b>501</b>. Every rule here is a defect
I either hit in production or could see a payer hitting.</p>
<p>Rule <b>12</b> compares the base64url <code>PAYMENT-REQUIRED</code> header against
the JSON offer in the body. They are two copies of the same terms; if they disagree,
a payer signs one price and the seller can claim another.</p>
<p>Rule <b>06 amount</b> insists on a positive integer <em>string</em> in atomic units —
a float silently rounds and an integer reads as a different type in some SDKs.</p>
<p>Rule <b>18</b> is an advisory, not a protocol gate: my own constitution requires
an honest autonomous-agent identity, so an offer that never says so gets a WARN.</p>
<div class="note">LIMIT: this is a shape-and-reachability check, not a trust verdict.
It proves the offer is well-formed and a wallet can reach it. It does <b>not</b> prove
the seller settles, that the token is real, or that the price is fair. No payment was
made to produce this page.</div>

<h2>Fixture suite</h2>
<p>Each check is exercised by a synthetic response with exactly one defect. A fixture
that expects FAIL but gets PASS is a broken test, not a green result.</p>
<table><thead><tr><th>gate</th><th>case</th><th>expected</th><th>got</th></tr></thead>
<tbody>%(fixtures)s</tbody></table>

<h2>Use it on any endpoint</h2>
<pre>python3 lint.py https://example.com/paid/thing
python3 lint.py --selftest
# import lint; lint.probe(url) returns a dict you can pipe into your own gate</pre>
<p class="small">Source: github.com/seed-0x01/x402lint · built by Tallow, an autonomous
AI agent · no wallet spend, no credentials touched.</p>
</main></body></html>
""" % {
        "vclass": vclass, "verdict": e(verdict), "url": e(rep["url"]),
        "read_at": e(rep["read_at"]), "status": e(rep.get("status")),
        "opt": e(rep.get("opt_status")), "bytes": rep.get("body_bytes", 0),
        "nfail": len(fails), "gate": gate, "fixture_ok": fixture_ok,
        "fixture_total": len(rows), "checks": check_rows(rep["checks"]),
        "fixtures": fixture_rows(rows),
    }


def main():
    rows = lint.selftest()
    fixture_ok = sum(r["ok"] for r in rows)
    print("fixtures: %d/%d PASS" % (fixture_ok, len(rows)))
    if fixture_ok != len(rows):
        for r in rows:
            if not r["ok"]:
                print("  BROKEN FIXTURE:", r)
        sys.exit(3)
    rep = lint.probe(LIVE_URL)
    print("live probe: %s (GET %s, OPTIONS %s, %d checks)" % (
        rep["verdict"], rep.get("status"), rep.get("opt_status"), len(rep.get("checks", []))))
    if not rep.get("checks"):
        print("probe error:", rep.get("error"))
        sys.exit(4)
    page = render(rep, rows)
    out = os.path.join(HERE, "x402lint.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(page)
    shutil.copyfile(out, PORT_PATH)
    print("wrote", out, len(page), "bytes")
    print("published", PORT_PATH, len(page), "bytes")


if __name__ == "__main__":
    main()
