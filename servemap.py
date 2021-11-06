#!/usr/bin/env python3
"""
servemap — lightweight HTTP stack fingerprinting for legacy-domain surveys.

Answers, per domain: alive? what server? what backend language leaks? which
CDN fronts it? session cookies present? parked/dead?

Built for archaeology over attack: the goal of a census pass is deciding
*whether a host is worth a second look*, not enumerating it. Read-only by
design: GET/HEAD only, no credential probing, no injection payloads.

Usage:
  servemap.py domains.txt -o census.tsv [-j 12]
"""
import argparse
import concurrent.futures
import http.client
import socket
import ssl
import sys
import urllib.parse

UA = "servemap/1.3 (+research census; contact in profile)"
CDNS = ("cloudflare", "akamai", "fastly", "cloudfront", "ddos-guard", "imperva",
        "sucuri", "wpxcloud", "namecheap-nginx", "parking")

def fetch(host, https=True, timeout=10):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, timeout=timeout, context=https and ctx or None) \
            if https else http.client.HTTPConnection(host, timeout=timeout)
        conn.request("HEAD", "/", headers={"User-Agent": UA, "Host": host})
        r = conn.getresponse()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        conn.close()
        return r.status, hdrs
    except Exception:
        return None, {}

def classify(host):
    status, h = fetch(host, https=True)
    scheme = "https"
    if status is None:
        status, h = fetch(host, https=False)
        scheme = "http"
    if status is None:
        return (host, "DEAD", "", "", "", "")
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    setc = h.get("set-cookie", "")
    cookies = ""
    for marker in ("PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "_session", "csrftoken", "ci_session"):
        if marker.lower() in setc.lower():
            cookies += marker + ";"
    cdn = next((c for c in CDNS if c in (server + h.get("via", "")).lower()), "")
    return (host, f"{scheme}:{status}", server[:40], powered[:30], cookies.rstrip(";"), cdn)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("infile")
    ap.add_argument("-o", "--out", default="-")
    ap.add_argument("-j", "--workers", type=int, default=12)
    a = ap.parse_args()
    domains = [l.strip() for l in open(a.infile) if l.strip() and not l.startswith("#")]
    out = open(a.out, "w") if a.out != "-" else sys.stdout
    out.write("domain\tstatus\tserver\tpowered\tcookies\tcdn\n")
    with concurrent.futures.ThreadPoolExecutor(a.workers) as ex:
        for row in ex.map(classify, domains):
            out.write("\t".join(row) + "\n")
    if out is not sys.stdout:
        out.close()

if __name__ == "__main__":
    main()
