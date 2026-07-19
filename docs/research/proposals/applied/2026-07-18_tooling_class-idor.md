# PROPOSAL (proposal) for docs/knowledge/class-idor.md — tooling 2026-07-18
_Review and apply manually; not auto-merged into the KB._

## Autoswagger — automated unauth Swagger/OpenAPI broken-authz scanner (added 2026-07-18)
`intruder-io/autoswagger` (OSS, Python) discovers Swagger/OpenAPI specs (direct file, Swagger-UI paths,
common default paths) and probes every documented endpoint **unauthenticated, GET-only by default**,
flagging any 200 that shouldn't be reachable without auth, then screens the response for PII (Presidio),
secrets (regex), or oversized payloads. This matches our safe-probe doctrine exactly (unauth, non-mutating,
no creds) — treat a hit as a provenance-confirmed LEAD for the IDOR/BAC candidate ranker, same tier as
`recon_idor_candidates.py` output, never auto-CONFIRMED. **Never pass its `-risk` flag** (enables
mutating POST/PUT/PATCH/DELETE testing) in the autonomous lane — GET-only always. Run it wherever
jsintel/kiterunner/params surfaces a `/swagger.json`, `/openapi.json`, or `/swagger-ui.html` on an
in-scope+paying host.

## Hadrian — authed role-based BOLA/BFLA framework, human-in-the-loop only (added 2026-07-18)
`praetorian-inc/hadrian` (Go, Apache-2.0) automates cross-role BOLA/BFLA testing over REST/GraphQL/gRPC
given YAML role definitions + credentials for 2+ accounts; it performs setup→attack→verify and explicitly
creates/mutates/deletes probe resources. This is a fit ONLY for our human-in-the-loop, 2-owned-account
authed-IDOR SOP — never the autonomous pipeline (it is not unauth-safe or read-only). Small project
(v1.0.0, Mar 2026, 67 stars) — treat as a candidate accelerant for the manual swap-test step once 2 owned
accounts exist on a target with a published spec, not yet a trusted default.
