# Todo: mehrere Ziele pro Name (CNAME, Round-Robin)

> Archived 2026-11-02 — shipped. Specs: [`SPEC-policy.md`](../../docs/SPEC-policy.md),
> [`SPEC-web-ui.md`](../../docs/SPEC-web-ui.md). Log: [`progress.md`](../progress.md).

Wunsch (Owner, 2026-10-29): ein Name soll mehrere Ziele haben können, auch bei CNAME.

## Randbedingungen
- DNS erlaubt pro Name genau einen CNAME; Cloudflare lehnt mehrere ab. Mehrere Ziele sind daher **nur lokal** möglich.
- Antwort pro Query: **ein** CNAME-Ziel, rotierend (Round-Robin), nie mehrere CNAMEs in einer Antwort.
- A/AAAA/TXT/MX/SRV dürfen regulär mehrere Werte im RRset haben.

## Heute (erledigt 2026-11-02)
- `rdata` und Overrides sind ein Wert oder eine Liste; ein String bleibt gültig.
- Lokal: A/AAAA/TXT/MX/SRV als RRset, CNAME-Ziele rotierend (ein Ziel pro Antwort).
- `GET/PUT/POST /api/v1/policy/records` lesen und schreiben die Liste.
- UI: mehrere lokale Werte; Cloudflare bleibt ein Einzelwert, mit Hinweis bei CNAME.
- SPEC-policy und SPEC-web-ui beschreiben das Verhalten.

## Offen
- [x] Policy-Modell: `rdata` → Liste (rückwärtskompatibel: String bleibt gültig), Overrides analog.
- [x] Resolver (`local_records`): Mehrfachwerte ausliefern; CNAME rotierend, A/AAAA als RRset.
- [x] Control-API `/policy/records`: Liste lesen/schreiben.
- [x] UI-Editor: mehrere Werte je Name/Typ; Cloudflare-Seite bleibt Einzelwert (Hinweis bei CNAME).
- [x] SPEC-policy / SPEC-web-ui: Verhalten dokumentieren.

Abhängigkeit: erst nach der Zonenauswahl auf der Namen-Seite (gleiche Datei).
