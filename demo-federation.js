/*
HWT Demo: Spontaneous Cross-Domain Federation

deno run -A ./demo-federation.js

What this demonstrates:

Any two HWT issuers can verify each other's tokens without prior coordination —
no registration, no shared secrets, no federation agreement. Each issuer publishes
its public keys and origin metadata at well-known endpoints (spec §6, §7). Any
verifier that can reach those endpoints can verify any token from that issuer.

This is spontaneous federation: hostA and hostB become interoperable the moment
both publish conformant well-known endpoints. The verification algorithm (spec §12)
runs identically in both directions — neither host is the identity provider for
the other.

SCENARIO:
1. hostA issues a service token → hostB verifies it with no prior knowledge of hostA
2. hostB issues a service token → hostA verifies it with no prior knowledge of hostB
3. Each host's hwt.json (spec §7) declares its capabilities — verifiers use this
   to discover authz schemas, aud requirements, and service endpoints
4. Neither host is privileged — the same algorithm runs in both directions
*/

import { ensureServers, hostA, hostB, get, post, checkInstance } from './demo_hosts.js';
await ensureServers();

function tokenPreview(token){
	return token.length > 80 ? token.slice(0, 40) + '…' + token.slice(-20) : token;
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main(){
	console.log(`
	HWT Demo: Spontaneous Cross-Domain Federation

── prerequisites ──────────────────────────────────────────────────────────

0) Checking instances
	`);

	const infoA = await checkInstance(hostA, 'Service A (hostA)');
	const infoB = await checkInstance(hostB, 'Service B (hostB)');

	console.log(`
	Two independent services — independent key pairs, no shared secrets,
	no prior contact between them.
	hostA kid: ${infoA.kid}
	hostB kid: ${infoB.kid}

── step 1: ──

	HWT (spec §1 — "Origin sovereignty"): a verifier that can reach the issuer's
	well-known endpoints can verify any token from that issuer. No registration.
	No client_id. No prior agreement. The trust anchor is the issuer's domain
	and the TLS path to it (spec §11.1) — not a central registry.
	`);

	// ── step 2: hostA issues a service token ──────────────────────────────────

	console.log(`
── step 2: hostA issues a service token ───────────────────────────────────

2) Issuer: hostA   subject: svc:api-gateway   authz: RBAC/1.0.2 roles: [service]
	`);

	const { token: tokenA, tid: tidA } = await post(`${hostA}/api/token`, {
		payload: {
			iss:   hostA,
			sub:   'svc:api-gateway',
			authz: { scheme: 'RBAC/1.0.2', roles: ['service'] }
		},
		expiresInSeconds: 3600
	});

	console.log(`
	Token issued by hostA
	token: ${tokenPreview(tokenA)}
	tid:   ${tidA}
	iss:   ${hostA}
	sub:   svc:api-gateway
	authz: { scheme: 'RBAC/1.0.2', roles: ['service'] }
	del:   [] — root token, no delegation history
	`);

	// ── step 3: hostB verifies hostA's token — no prior knowledge of hostA ───

	console.log(`
── step 3: hostB verifies hostA's token — no prior knowledge of hostA ─────

3) hostB calls /api/verify-external (spec §12 verification path)
   Fetches: ${hostA}/.well-known/hwt-keys.json  (spec §6 key discovery)

   hostB has never seen hostA. No registration. No shared secret.
   The issuer origin (${hostA}) is inside the token — the verifier
   constructs the JWKS URL from it at verification time.
	`);

	const verifyAatB = await post(`${hostB}/api/verify-external`, { token: tokenA });

	if(!verifyAatB.ok){
		throw new Error(`hostA token rejected by hostB: ${verifyAatB.error}`);
	}

	console.log(`
	Signature valid — hostA token verified by hostB
	verified sub:   ${verifyAatB.data.sub}
	verified authz: ${ JSON.stringify(verifyAatB.data.authz) }
	verified iss:   ${verifyAatB.data.iss}
	JWKS fetched:   ${verifyAatB._external?.jwksUrl}
	Not expired · Signature valid
	`);

	// ── step 4: hostB issues a service token ──────────────────────────────────

	console.log(`
── step 4: hostB issues a service token ───────────────────────────────────

4) Issuer: hostB   subject: svc:data-store   authz: RBAC/1.0.2 roles: [service]
	`);

	const { token: tokenB, tid: tidB } = await post(`${hostB}/api/token`, {
		payload: {
			iss:   hostB,
			sub:   'svc:data-store',
			authz: { scheme: 'RBAC/1.0.2', roles: ['service'] }
		},
		expiresInSeconds: 3600
	});

	console.log(`
	Token issued by hostB
	token: ${tokenPreview(tokenB)}
	tid:   ${tidB}
	iss:   ${hostB}
	sub:   svc:data-store
	authz: { scheme: 'RBAC/1.0.2', roles: ['service'] }
	del:   [] — root token, no delegation history
	`);

	// ── step 5: hostA verifies hostB's token — no prior knowledge of hostB ───

	console.log(`
── step 5: hostA verifies hostB's token — no prior knowledge of hostB ─────

5) hostA calls /api/verify-external (spec §12 verification path)
   Fetches: ${hostB}/.well-known/hwt-keys.json  (spec §6 key discovery)
	`);

	const verifyBatA = await post(`${hostA}/api/verify-external`, { token: tokenB });

	if(!verifyBatA.ok){
		throw new Error(`hostB token rejected by hostA: ${verifyBatA.error}`);
	}

	console.log(`
	Signature valid — hostB token verified by hostA
	verified sub:   ${verifyBatA.data.sub}
	verified authz: ${ JSON.stringify(verifyBatA.data.authz) }
	verified iss:   ${verifyBatA.data.iss}
	JWKS fetched:   ${verifyBatA._external?.jwksUrl}
	Not expired · Signature valid
	`);

	// ── step 6: metadata discovery — hwt.json declares issuer capabilities ────

	console.log(`
── step 6: origin metadata — hwt.json declares issuer capabilities ────────

6) Fetching /.well-known/hwt.json from both hosts (spec §7)

   Verifiers fetch this document to discover declared authz schemas,
   audience requirements, delegation depth limits, and service endpoints.
   When absent, verifiers apply documented field defaults (spec §7).
   The document is informational for schema discovery and configuration;
   cryptographic verification (spec §12) does not depend on it.
	`);

	const metaA = await get(`${hostA}/.well-known/hwt.json`);
	const metaB = await get(`${hostB}/.well-known/hwt.json`);

	console.log(`
	hostA origin metadata (spec §7):
	  issuer:               ${metaA.issuer}
	  authz_schemas:        ${ JSON.stringify(metaA.authz_schemas) }
	           ↑ schemas this issuer may use — informational (spec §7, §A.5)
	  authz_evaluation:     ${metaA.authz_evaluation}
	           ↑ "all" = every scheme in array authz must pass (spec §4.3)
	  aud_required:         ${metaA.aud_required}
	  max_delegation_depth: ${metaA.max_delegation_depth}
	  endpoints.revocation: ${ metaA.endpoints?.revocation ?? '(none declared)' }
	           ↑ library extension — not in HWT spec (spec §13)

	hostB origin metadata (spec §7):
	  issuer:               ${metaB.issuer}
	  authz_schemas:        ${ JSON.stringify(metaB.authz_schemas) }
	  authz_evaluation:     ${metaB.authz_evaluation}
	  aud_required:         ${metaB.aud_required}
	  max_delegation_depth: ${metaB.max_delegation_depth}
	  endpoints.revocation: ${ metaB.endpoints?.revocation ?? '(none declared)' }
	`);

	// ── step 7: no hierarchy — same algorithm, both directions ────────────────

	console.log(`
── step 7: no hierarchy — same verification algorithm, both directions ─────

7) Both hosts ran the identical spec §12 verification algorithm.
   Neither is an "identity provider" for the other.
   Either can issue tokens the other will accept.
   No trust hierarchy. No federation agreement between the organizations.

   Minimum required infrastructure per issuer:
	   /.well-known/hwt-keys.json   (spec §6 — MUST publish)
	   /.well-known/hwt.json        (spec §7 — SHOULD publish)

   A verifier that fetches these two documents from any issuer's origin can
   verify any token from that issuer. The well-known path is standardized —
   no out-of-band JWKS URL configuration, no discovery document bootstrap.
	`);

	// ── summary ────────────────────────────────────────────────────────────────

	console.log(`
── summary ────────────────────────────────────────────────────────────────

	Spontaneous federation — both directions:

	svc:api-gateway @ hostA → verified by hostB  (JWKS from ${hostA})
	svc:data-store  @ hostB → verified by hostA  (JWKS from ${hostB})

	Zero pre-coordination. Zero shared secrets. Zero registration.
	Trust anchor: each issuer's domain and the TLS path to it (spec §11.1).

	...

	OAuth 2.0 / OIDC comparison:

	  OAuth client registration    → HWT: not required
	  OIDC discovery document      → HWT: hwt.json (spec §7 — SHOULD publish)
	  OIDC token endpoint          → HWT: out of scope (spec §13 — issuance)
	  OIDC introspection endpoint  → HWT: not required; local verification (spec §12)
	  Shared IdP assumption        → HWT: origin sovereignty (spec §1)

	Production posture (spec §11.1, §A.7): deploying with a pre-registered issuer
	allowlist eliminates the unknown-origin SSRF attack surface (spec §11.2).
	The unknown-issuer accept path demonstrated here is correct for open
	deployments; pre-registration is the recommended default when the set of
	trusted issuers is known in advance.

	`);

	Deno.exit();
}

main().catch(error => {
	console.warn(`Error:`, error.message);
	console.error(error);
	Deno.exit(1);
});
