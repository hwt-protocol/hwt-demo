# hwt-demo

Development server and scenario demos for the [HWT (Hash Web Token) protocol](../hwt-protocol/).

[canonical documentation](https://www.jimmont.com/hwt/hwt-demo) [issues](https://github.com/hwt-protocol/hwt-demo/issues)

HWT is a stateless, cross-domain authorization token protocol. Any domain is a valid issuer. Tokens are verifiable by anyone who can reach the issuer's public keys — no central provider, no pre-configuration between parties.

## Demos

> These demos facilitate use — they are not comprehensive references or dogma. They layer application assumptions on top of the protocol (revocation, delegation APIs, server conventions) that are useful but not part of the HWT spec. For what the protocol actually guarantees, see the [SPEC.md](../hwt-protocol/SPEC.md). For shared vocabulary, see [CONVENTIONS.md](../hwt-protocol/CONVENTIONS.md).

### Scenario demos

- [demo-agent-chain.js](demo-agent-chain.js)            AI agent delegation chain
- [demo-del-verify.js](demo-del-verify.js)             del[] chain verification and revoked-link detection
- [demo-multiparty.js](demo-multiparty.js)             Multi-party joint authorization
- [demo-federation.js](demo-federation.js)             Spontaneous cross-domain federation
- [demo-mesh.js](demo-mesh.js)                   Service mesh delegation chain
- [demo-partner-api.js](demo-partner-api.js)            Partner API access and audience binding
- [demo-edge.js](demo-edge.js)                   Stateless verification at the edge
- [demo-revocation-strategies.js](demo-revocation-strategies.js)  Short-lived tokens vs explicit revocation — strategy guide

### Deployment baselines

Starting points for real deployments. Adapt to your infrastructure. These scripts do not use `demo_hosts.js` and do not call `ensureServers()` — they are standalone.

- [demo-hono-deno.js](demo-hono-deno.js)        Deno + Hono — asymmetric keys (Ed25519 / ECDSA)
- [demo-hono-cloudflare.js](demo-hono-cloudflare.js)  Cloudflare Workers + Hono — asymmetric keys
- [demo-hmac-deno.js](demo-hmac-deno.js)        Deno — HMAC, single-party, no infrastructure
- [demo-hmac-cloudflare.js](demo-hmac-cloudflare.js)  Cloudflare Workers — HMAC, shared secret

HMAC is for single-party deployments (spec §2). Use the asymmetric baselines for anything that requires cross-origin verification or delegation chains.

## Requirements

[Deno](https://deno.com/) — no other dependencies.

## Quick start — two-instance cross-origin demo

```sh
# Terminal A — auth server
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8888 --hwt-keys=.hwt-keys-hosta.json

# Terminal B — second service
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8889 --hwt-keys=.hwt-keys-hostb.json
```

Open [http://localhost:8888](http://localhost:8888) and [http://localhost:8889](http://localhost:8889).

**What to do:** Create a token on A → paste it into "Verify External" on B. B fetches A's JWKS at runtime and verifies the signature with no prior configuration.

`--hwt-keys` saves your key pair to a file so tokens survive server restarts. Omit it for in-memory-only keys.

## Demo scripts

Each script runs a complete scenario against live server instances. `demo_hosts.js` starts them automatically if they are not already running (ports 8888, 8889, 8880):

```sh
deno run -A demo-agent-chain.js
deno run -A demo-del-verify.js
deno run -A demo-multiparty.js
deno run -A demo-federation.js
deno run -A demo-mesh.js
deno run -A demo-partner-api.js
deno run -A demo-edge.js
deno run -A demo-revocation-strategies.js
```

Or start the servers manually in separate terminals first (see the quick start above), then run any demo script.

---

### [`demo-agent-chain.js`](demo-agent-chain.js) — AI agent delegation chain

A user authenticates with an auth server and delegates authority to an AI agent on a separate service. That agent delegates to a sub-agent on a third service. The final token carries the full cryptographic provenance chain (`del[]`), covered by the outer token's signature — tamper-proof without a central coordinator. Each link is independently verifiable against the respective issuer's published keys.

Walks through: root token creation → cross-server delegation (agent-1 on hostB) → second-hop delegation (agent-2 on hostA) → cross-origin verification of the final token → root token revocation showing application-layer chain invalidation.

---

### [`demo-del-verify.js`](demo-del-verify.js) — del[] chain verification

Demonstrates the distinction between protocol verification and application-layer revocation checking — two distinct outcomes spec §12 explicitly separates.

After building a two-hop chain (`user:alice → svc:agent-1 → svc:agent-2`), the script revokes alice's root token and shows the critical moment: protocol verification (`/api/verify-external`) still passes — the outer signature is valid, which is correct. Application-layer chain verification (`/api/verify-chain`) fails — the revocation list for alice's issuer contains the revoked `tid`. The outer token was not re-signed; its signature remains valid. Only the application-layer state check catches the invalidation.

Revocation checking is a library feature built on top of HWT. Spec §13 explicitly places revocation outside protocol scope. The protocol defines chain structure and signature guarantee — what you do with it is yours to decide.

---

### [`demo-multiparty.js`](demo-multiparty.js) — multi-party joint authorization

Two independent organizations each issue approver tokens to their own principals. A coordinator service verifies both tokens cross-origin against each issuer's JWKS — no shared identity provider, no prior agreement between the organizations. Only when both verify does the coordinator issue a joint authorization token using a private authz schema (spec §4.2) embedding both approver identities. Any downstream service can verify the coordinator token and inspect the quorum record from the token alone, without re-contacting the original issuers.

Demonstrates why `del[]` does not apply here: it is a linear delegation chain with no multi-parent form. The approver identities are application data in `authz`, not protocol delegation records. Also shows that revoking one party's root token at their issuer does not propagate to the coordinator's token store — each token's state is managed at its own issuer (spec §13).

---

### [`demo-federation.js`](demo-federation.js) — spontaneous cross-domain federation

Any two HWT issuers interoperate the moment both publish conformant well-known endpoints — no registration, no shared secrets, no federation agreement. This script verifies tokens in both directions: hostA token verified at hostB, hostB token verified at hostA. Neither host is the identity provider for the other; the same spec §12 algorithm runs identically in both directions.

Also demonstrates origin metadata discovery (`/.well-known/hwt.json`, spec §7): what the document contains, what each field means, and what verifiers do when it is absent (apply documented field defaults and continue — spec §7).

---

### [`demo-mesh.js`](demo-mesh.js) — service mesh delegation chain

Service-to-service authentication across a three-service mesh without a mesh CA, without mTLS, and without a service mesh. A user token from the auth service (hostA) flows through a gateway (hostB) and a backend (hostC), each hop verified against the prior service's JWKS and re-delegated. The final token carries `del[]` entries for every intermediate — independently verifiable from the token alone.

`authz` is traced through every hop explicitly: viewer → viewer → viewer. The role does not change because spec §8.1 is normative — derived token authz must be equal to or a strict subset of the subject token's authz. Revocation at the root collapses the chain at the application layer.

---

### [`demo-partner-api.js`](demo-partner-api.js) — partner API access and audience binding

B2B API integration without shared credentials. A partner organization reads the consuming API's `/.well-known/hwt.json` to discover its requirements, then issues a token with `aud` bound to that specific API and array `authz` (spec §4.3) combining an RBAC schema with CONVENTIONS.md jurisdiction vocabulary (`GDPR/2.0/DE`). The consuming API verifies cross-origin, then enforces audience matching at the application layer (spec §12 step 9).

The `aud` mismatch path is demonstrated explicitly: a cryptographically valid token bound to a different service is refused at the application layer after signature verification passes. This is the confused deputy mitigation (spec §11.4).

Also covers: `authz_evaluation: "all"` requiring both schemes to satisfy evaluation; and the CONVENTIONS.md disclaimer that carrying a jurisdiction claim is not compliance — it is structural vocabulary.

---

### [`demo-edge.js`](demo-edge.js) — stateless verification at the edge

The same token verified independently at two nodes (hostB, hostC) with zero round-trips to the issuer (hostA) after the initial JWKS fetch.

Also covers: the `kid`-not-found forced re-fetch and its rate-limit requirement (spec §6, §11.7); the pre-registered vs unknown-issuer security tradeoff (spec §11.1, §11.2, §A.7) and why pre-registration is the recommended production posture.

---

### [`demo-revocation-strategies.js`](demo-revocation-strategies.js)` — revocation strategy guide

The most common practical question for adopters: when do you shorten the token lifetime vs build a revocation system? Three strategies demonstrated with live tokens:

- **Short-lived tokens** — a 5-second token expires on screen. Zero infrastructure. Exposure window equals token lifetime. This is the primary mechanism (spec §1).
- **Explicit revocation** — a 1-hour token is rejected within seconds of issuance. Immediate invalidation. Infrastructure cost: revocation endpoint on the verification critical path.
- **Hybrid** — a 15-minute token. Normal case uses natural expiry. Revocation handles edge cases only. The practical default for most production systems.

Includes a decision matrix keyed to deployment context (financial API, general user session, internal service, long-lived agent delegation) using lifetime ranges from spec §A.1, and four questions an adopter should answer before choosing a strategy. Frames revocation as a complement to a well-chosen lifetime, not a substitute for one.

---

## Server endpoints

[`http.js`](http.js) is a development and demonstration server. It is not hardened for production.

### Protocol endpoints (spec-defined)

| Method | Path | Spec | Description |
|---|---|---|---|
| GET | `/.well-known/hwt-keys.json` | §6 | JWKS public keys — required for cross-origin verification |
| GET | `/.well-known/hwt.json` | §7 | Issuer metadata — authz schemas, aud policy, delegation depth, endpoint declarations |

### Library extension endpoints

These endpoints implement behavior layered on top of the protocol. Revocation and delegation are application concerns — spec §13 explicitly places them outside protocol scope.

| Method | Path | Description |
|---|---|---|
| GET | `/.well-known/hwt-revoked.json` | Revocation list — declared in `hwt.json` under `endpoints.revocation` |
| POST | `/api/token/delegate` | Create a delegated token — populates `del[]` per spec §8.1 chain construction rules |
| POST | `/api/revoke` | Revoke a token by `tid` or token string |
| POST | `/api/revoke/clear` | Clear revocation list — dev convenience |

### Verification endpoints

| Method | Path | Protocol | Application-layer | Description |
|---|---|---|---|---|
| POST | `/api/verify` | ✓ sig + expiry | ✓ local revocation | Verify against local keys + check this server's revocation list |
| POST | `/api/verify-external` | ✓ sig + expiry | — | Cross-origin JWKS fetch and verify per spec §12 |
| POST | `/api/verify-chain` | ✓ sig + expiry | ✓ full del[] revocation walk | Verify + fetch each del[] entry's issuer revocation list |
| POST | `/api/decode` | — | — | Decode payload — no signature check |

**The distinction between these endpoints matters.** `/api/verify-external` runs the spec §12 verification algorithm: signature, expiry, `del[]` structural integrity (guaranteed by the outer signature). This is what a conformant verifier implements. `/api/verify-chain` adds application-layer state checking on top — it fetches each `del[]` entry's issuer's revocation list and confirms none are revoked. A token can pass protocol verification and fail chain verification if a delegator's authorization has been revoked since the token was issued. See `demo-del-verify.js` for a step-by-step demonstration of this distinction.

### Token and key management

| Method | Path | Description |
|---|---|---|
| POST | `/api/token` | Create a signed token |
| GET | `/api/info` | Server origin, kid, key type |
| GET | `/api/keys` | Full key config including private key — dev only, never expose |
| POST | `/api/keys/generate` | Regenerate keys |
| POST | `/api/keys/import` | Restore a prior key config |

## Arguments

### `http.js`

```
--port=8888          Port to listen on (default: 8888)
--hwt-keys=filename  Key file path for persistence across restarts
```

Without `--hwt-keys`, keys are generated in memory and lost on restart. Ed25519 keys are generated by default.

## Related

- [HWT Protocol Specification](../hwt-protocol/)
- [hwtr-js reference library](../hwtr-js/)

## License

Apache License 2.0 — see [LICENSE](./LICENSE).
