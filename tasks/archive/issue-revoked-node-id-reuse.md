# DONE 2026-11-02 — Widerrufener Knoten blockiert seine Node-ID dauerhaft (`cluster.node.already_joined`)

Resolved. A join token can be minted for a **revoked** node id; redeeming it replaces
the old row (new fingerprint, `revoked` cleared). An **active** id still returns
`cluster.node.already_joined`. The old certificate stops working because the stored
fingerprint changed (`revoked_node_id_can_be_rejoined_and_old_certs_stop_working` in
`crates/dnscraft-cluster/src/store.rs`). `DELETE /api/v1/cluster/nodes/{id}?remove=true`
can also delete an already revoked node. The UI text for `cluster.node.already_joined`
says to revoke first (`error_cluster_node_already_joined`, de/en).

---

# Widerrufener Knoten blockiert seine Node-ID dauerhaft (`cluster.node.already_joined`)

## Problem

Nach dem Widerrufen eines Unterknotens (z. B. `dns2`) bleibt dessen Eintrag mit Status
„Widerrufen“ in der Knotenliste bestehen. Ein neues Join-Token für dieselbe Node-ID lässt
sich danach nicht mehr ausstellen:

```
POST /api/v1/cluster/join-tokens  {"node_id": "dns2"}
→ cluster.node.already_joined
```

Die UI zeigt dazu nur „Ein unerwarteter Fehler ist aufgetreten.“ mit dem Rohcode.

## Reproduktion

1. Cluster mit Master `dns1` und Unterknoten `dns2`.
2. Knotenliste → `dns2` → „Widerrufen“ → bestätigen.
3. „Join-Token ausstellen“ → Knoten-ID `dns2` → „Token erzeugen“.

Erwartet: Token wird ausgestellt, der Ersatzknoten kann mit `dns2` beitreten.
Tatsächlich: `cluster.node.already_joined`.

## Praktischer Anlass

Ein Unterknoten wird auf andere Hardware umgezogen (elmo → waldo) und soll seine
Node-ID, seinen Hostnamen (`ns2.dns.2s4u.de`) und seine Rolle behalten. Das ist ohne
Umbenennung nicht möglich.

## Zu klären

- Soll ein widerrufener Knoten **entfernbar** sein („Entfernen“ in den Knotendetails,
  nur für Status „Widerrufen“, nur Admin)?
- Oder soll ein Join-Token für eine widerrufene Node-ID **erlaubt** sein und den alten
  Eintrag (Zertifikat-Fingerabdruck, Beitrittsdatum) ersetzen?
- Die Zertifikate des alten Knotens müssen in beiden Fällen ungültig bleiben.

## Vorschlag

Beides ist klein: Ein Token für eine widerrufene Node-ID darf ausgestellt werden; beim
erfolgreichen Join wird der alte Eintrag ersetzt. Zusätzlich ein Fehlertext für
`cluster.node.already_joined` in der UI, der sagt, wie es weitergeht, statt „unerwarteter
Fehler“.

## Akzeptanz

- Widerrufen → Token für dieselbe ID → Join klappt; alter Fingerabdruck wird abgelehnt.
- Token für eine **aktive** Node-ID bleibt abgelehnt.
- UI zeigt für `cluster.node.already_joined` eine verständliche Meldung (de/en).
- Tests: Join-Procedure in SPEC-cluster.md (Token: wrong `node_id`, replay) um
  „widerrufene ID“ ergänzen.
