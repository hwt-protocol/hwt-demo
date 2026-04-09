/*
HWT Demo: Partner API — Audience Binding and Array Authorization

deno run -A ./demo-partner-api.js

What this demonstrates:

A partner organization (hostB) issues a scoped token for their engineer to call
a specific API at hostA. The token carries audience binding (spec §3.2) to prevent
cross-service replay (spec §11.4 — confused deputy), and uses array authz (spec §4.3)
combining an RBAC schema with jurisdiction vocabulary from CONVENTIONS.md.

The consuming API enforces audience matching in the application layer — this is
spec §12 step 9 behavior, and it is the consuming application's responsibility,
not the protocol's.

Key spec properties shown:
  aud binding prevents cross-service replay — spec §3.2, §11.4
  Array authz: RBAC/1.0.2 + private jurisdiction schema — spec §4.3
  authz_evaluation "all": both schemes must satisfy (spec §4.3, §7)
  Application-layer aud enforcement — spec §12 step 9, step 10
  CONVENTIONS.md jurisdiction vocabulary in practice

SCENARIO:
1. Consuming API (hostA) publishes hwt.json — partner reads it to discover aud requirements
2. Partner (hostB) issues a scoped partner token (aud=hostA, array authz)
3. Partner token verified cross-origin at hostA — spec §12 cryptographic path
4. Application-layer aud enforcement — consuming API confirms aud matches its identifier
5. Aud mismatch rejected — token intended for a different service is refused
6. authz_evaluation "all" — consuming app must satisfy both authz schemes
*/

import { ensureServers, hostA, hostB, get, post, checkInstance } from './demo_hosts.js';
await ensureServers();

function tokenPreview(token){
	return token.length > 80 ? token.slice(0, 40) + '…' + token.slice(-20) : token;
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main(){
	console.log(`
	HWT Demo: Partner API — Audience Binding and Array Authorization

── prerequisites ──────────────────────────────────────────────────────────

0) Checking instances
	`);

	const infoA = await checkInstance(hostA, 'Consuming API (hostA)');
	const infoB = await checkInstance(hostB, 'Partner org   (hostB)');

	console.log(`
	hostA is the API accepting partner tokens.
	hostB is the partner organization issuing tokens to their engineers.
	hostA kid: ${infoA.kid}  hostB kid: ${infoB.kid}

── step 1: ───────

	HWT expiry (spec §2):
	  · Expiry is field 4 in the wire format: hwt.signature.kid.EXPIRES.format.payload
	  · Checked in step 2 of the verification algorithm — before payload decode
	  · Cannot be omitted: a token without a valid expiry field cannot be parsed
	  · Cannot be extended post-issuance: the expiry field is part of the signed input

	Array authz (spec §4.3):
	  · HWT authz accepts an array of scheme objects — multiple authorization
	    frameworks active simultaneously on a single token
	  · The consuming application evaluates each scheme per authz_evaluation
	    (default: "all" — every scheme must pass)

	`);

	// ── step 2: partner reads hostA's hwt.json to discover API requirements ──

	console.log(`
── step 2: partner discovers hostA's API requirements via hwt.json ─────────

2) Partner fetches ${hostA}/.well-known/hwt.json  (spec §7)
   Discovers: aud_required, authz_schemas, authz_evaluation
   This is how a partner knows what to put in the token before issuing it.
	`);

	const apiMeta = await get(`${hostA}/.well-known/hwt.json`);

	console.log(`
	hostA origin metadata:
	  aud_required:         ${apiMeta.aud_required}
	  aud_array_permitted:  ${apiMeta.aud_array_permitted}
	  authz_schemas:        ${ JSON.stringify(apiMeta.authz_schemas) }
	  authz_evaluation:     ${apiMeta.authz_evaluation}
	           ↑ "all" — both schemes in an array authz must satisfy evaluation

	The partner will include aud=${hostA} in the token (even though aud is
	not declared required here — good practice per spec §11.4 to prevent
	confused deputy when tokens flow between services).

	The partner will use array authz combining RBAC roles with a private
	jurisdiction schema — carrying GDPR context per CONVENTIONS.md vocabulary.
	Private schemas use a URL-form scheme identifier (spec §4.4); the URL form
	is the unambiguous signal that this is not a community-convention schema.
	`);

	// ── step 3: partner issues a scoped token for their engineer ──────────────

	console.log(`
── step 3: partner (hostB) issues a scoped token for their engineer ────────

3) Issuer: hostB   subject: user:eng-7f2a   aud: ${hostA}
   authz: array — RBAC/1.0.2 + private jurisdiction schema (CONVENTIONS.md)
	`);

	// Array authz: RBAC schema + jurisdiction vocabulary (CONVENTIONS.md pattern)
	// Jurisdiction identifier: GDPR/2.0/DE — spec format: Regulation/Version/Country
	const partnerAuthz = [
		{ scheme: 'RBAC/1.0.2', roles: ['partner:read'] },
		{ scheme: '/schemas/jurisdiction/v1', jur: 'GDPR/2.0/DE' }
	];

	const { token: partnerToken, tid: partnerTid } = await post(`${hostB}/api/token`, {
		payload: {
			iss:   hostB,
			sub:   'user:eng-7f2a',
			aud:   hostA,
			authz: partnerAuthz
		},
		expiresInSeconds: 3600
	});

	console.log(`
	Partner token issued by hostB
	token:  ${tokenPreview(partnerToken)}
	tid:    ${partnerTid}
	iss:    ${hostB}
	sub:    user:eng-7f2a
	aud:    ${hostA}
	        ↑ audience bound to this specific API — prevents cross-service replay
	authz:  ${ JSON.stringify(partnerAuthz) }
	        ↑ array form (spec §4.3) — two active schemes on one token
	del:    [] — root token, no delegation history

	CONVENTIONS.md jurisdiction vocabulary:
	  GDPR/2.0/DE → format: Regulation/VocabVersion/ISO-3166-country
	  Carries no compliance guarantee — structural vocabulary only (CONVENTIONS.md intro)
	`);

	// ── step 4: hostA verifies the partner token cross-origin ─────────────────

	console.log(`
── step 4: hostA verifies partner token cross-origin (spec §12) ───────────

4) hostA calls /api/verify-external (spec §12 verification path)
   Fetches: ${hostB}/.well-known/hwt-keys.json  (spec §6 key discovery)

   Steps 1–7: cryptographic verification
   Steps 8–9: structural authorization validation (aud present — see step 5)
   Step 10:   return verified payload to consuming application
	`);

	const crossVerify = await post(`${hostA}/api/verify-external`, { token: partnerToken });

	if(!crossVerify.ok){
		throw new Error(`Partner token failed cross-origin verification: ${crossVerify.error}`);
	}

	console.log(`
	Signature valid — partner token verified by hostA
	verified sub:    ${crossVerify.data.sub}
	verified aud:    ${crossVerify.data.aud}
	verified authz:  ${ JSON.stringify(crossVerify.data.authz) }
	JWKS fetched:    ${crossVerify._external?.jwksUrl}
	Not expired · Signature valid
	`);

	// ── step 5: application-layer aud enforcement ──────────────────────────────

	console.log(`
── step 5: application-layer aud enforcement — spec §12 step 9 ────────────

5) The consuming application knows its own canonical identifier.
   spec §12 step 9: "If aud present as string: confirm it matches the
   verifier's own canonical identifier — reject if not."

   This check is the consuming application's responsibility (spec §12 step 10).
   The verification endpoint returns the verified payload; the application decides.
	`);

	// Consuming API's canonical identifier — configured at deploy time (spec §A.3)
	// "The verifier's canonical identifier for aud matching is its publicly-reachable
	// HTTPS origin URL, configured explicitly at deployment time — not derived from
	// request context." (spec §A.3)
	const myCanonicalId = hostA;
	const verifiedAud   = crossVerify.data.aud;
	const audMatches    = verifiedAud === myCanonicalId;

	console.log(`
	Application-layer aud check:
	  token aud:          ${verifiedAud}
	  this service is:    ${myCanonicalId}
	  aud matches:        ${audMatches}
	  decision:           ${ audMatches ? 'ACCEPT — aud matches this service' : 'REJECT — aud mismatch' }
	`);

	// ── step 6: aud mismatch — token intended for a different service ──────────

	console.log(`
── step 6: aud mismatch — token intended for a different service ───────────

6) Partner issues a token scoped to a different API (aud=${hostB}).
   hostA verifies the signature — cryptographically valid — then enforces
   aud at the application layer and rejects the request.

   This is the confused deputy mitigation (spec §11.4): a token with the
   right signature but the wrong audience cannot be replayed to this service.
	`);

	const { token: wrongAudToken } = await post(`${hostB}/api/token`, {
		payload: {
			iss:   hostB,
			sub:   'user:eng-7f2a',
			aud:   hostB,       // scoped to hostB, not hostA
			authz: partnerAuthz
		},
		expiresInSeconds: 3600
	});

	const wrongAudVerify = await post(`${hostA}/api/verify-external`, { token: wrongAudToken });

	const wrongAud      = wrongAudVerify.data?.aud;
	const mismatch      = wrongAud !== myCanonicalId;

	console.log(`
	Wrong-aud token verified (signature valid): ${wrongAudVerify.ok}
	token aud:       ${wrongAud}
	this service is: ${myCanonicalId}
	aud mismatch:    ${mismatch}
	application decision: ${ mismatch ? `REJECT — aud ${wrongAud} does not match this service (${myCanonicalId})` : 'ACCEPT' }

	The cryptographic check passed — the signature is valid. The audience
	check is what prevents cross-service replay. Without aud enforcement,
	a valid token issued for one service could be presented to any other.
	`);

	// ── step 7: array authz — both schemes must satisfy evaluation ────────────

	console.log(`
── step 7: array authz — authz_evaluation "all" (spec §4.3) ───────────────

7) The partner token carries two authz schemes. hostA declared
   authz_evaluation "all" in hwt.json — both must satisfy evaluation.

   Scheme 0 — RBAC/1.0.2:
	   ${ JSON.stringify(partnerAuthz[0]) }
	   Consuming application checks: does roles include what this endpoint requires?
	   partner:read → application grants read-only access to partner resources

   Scheme 1 — /schemas/jurisdiction/v1 (private schema):
	   ${ JSON.stringify(partnerAuthz[1]) }
	   GDPR/2.0/DE: CONVENTIONS.md jurisdiction vocabulary — EU GDPR, Germany
	   Consuming application checks: does this match the data residency policy
	   for the requested resource?

   Evaluation is the consuming application's responsibility (spec §13 — schema
   content and authorization evaluation are explicitly out of scope).

   Carrying a GDPR/2.0/DE claim does not make the issuer or consumer GDPR
   compliant — it is structural vocabulary, shared naming for coordination
   between parties who have never coordinated (CONVENTIONS.md introduction).
	`);

	// ── summary ────────────────────────────────────────────────────────────────

	console.log(`
── summary ────────────────────────────────────────────────────────────────

	Partner token flow:

	hostB issues:  user:eng-7f2a  aud=${hostA}
	               authz: [RBAC/1.0.2 partner:read] + [/schemas/jurisdiction/v1 GDPR/2.0/DE]
	hostA verifies: cross-origin JWKS fetch from ${hostB}
	                aud confirmed: ${hostA} ✓
	                authz_evaluation "all" — both schemes evaluated

	Aud binding (spec §3.2):
	  Token scoped to ${hostA} — cannot be replayed to any other service.
	  Prevents confused deputy (spec §11.4).
	  Best practice: always bind tokens to their intended recipient (spec §A.3).

	Array authz (spec §4.3):
	  Multiple authorization frameworks active on one token.
	  RBAC/1.0.2 from CONVENTIONS.md — community vocabulary for cross-domain interop.
	  /schemas/jurisdiction/v1 — private schema, URL form signals private (spec §4.4).
	  authz_evaluation "all" — both schemes must satisfy evaluation (spec §7).

	Application responsibility boundary (spec §12 step 10, §13):
	  Protocol: verify signature, check expiry, validate aud structure
	  Application: enforce aud value match, evaluate authz schemes, apply policy

	`);

	Deno.exit();
}

main().catch(error => {
	console.warn(`Error:`, error.message);
	console.error(error);
	Deno.exit(1);
});
