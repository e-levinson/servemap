# servemap

Lightweight HTTP stack fingerprinting for legacy-domain surveys — decide
*whether a host is worth a second look*, in one pass.

Read-only by design: HEAD/GET only, no credential probing, no injection
payloads. Built for censuses of long-dead infrastructure eras where 500+
domains need a first-glance verdict: alive, fronted, leaking, or parked.

## Output

```
domain  status      server          powered       cookies     cdn
foo.tld https:200   Apache          PHP/7.4.33    PHPSESSID;  -
bar.tld DEAD        -               -             -           -
```

## History

- **2021** v0.1 — banner grab over HEAD, single-threaded
- **2022** v0.5 — https+http fallback, thread pool
- **2023** v1.0 — cookie surface detection (session cookie taxonomy)
- **2024** v1.1 — CDN classification from server/via banners
- **2026** v1.3 — hardened TLS defaults, UA etiquette, TSV census mode

## License

MIT
