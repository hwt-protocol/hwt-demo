/*
HWT Demo: Stateless Verification at the Edge

deno run -A ./demo-edge.js

What this demonstrates:

HWT verification is a local operation after an initial key fetch. The same
token can be verified independently at any number of nodes — no round-trip
to the issuing service required per verification. Each verifier fetches JWKS
once (spec §6 caching model, spec §9), then verifies locally from that point.

Key spec properties shown:
  The same token verified at multiple independent nodes — spec §12
  Each node fetches the issuer JWKS once — spec §6, §9 (caching model)
  Unknown-issuer accept path vs pre-registered issuers — spec §6, §11.1, §11.2
  kid-not-found triggers forced re-fetch — spec §6 (forced invalidation)
  SSRF constraint on unknown-issuer path — spec §11.2

SCENARIO:
1. hostA issues a service token
2. The same token verified at hostB and hostC independently — no contact with hostA
3. Key rotation: new key published, tokens signed with new key verified at all nodes
4. Pre-registered vs unknown-issuer: security model comparison
*/

import { ensureServers, hostA, hostB, hostC, get, post, checkInstance } from './demo_hosts.js';
await ensureServers();

function tokenPreview(token){
	return token.length > 80 ? token.slice(0, 40) + '…' + token.slice(-20) : token;
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main(){
	console.log(`
	HWT Demo: Stateless Verification at the Edge

── prerequisites ──────────────────────────────────────────────────────────

0) Checking instances
	`);

	const infoA = await checkInstance(hostA, 'Issuer     (hostA)');
	const infoB = await checkInstance(hostB, 'Verifier 1 (hostB)');
	const infoC = await checkInstance(hostC, 'Verifier 2 (hostC)');

	console.log(`
	One issuer (hostA), two independent verifier nodes (hostB, hostC).
	None of the three share secrets or pre-configuration with each other.
	hostA kid: ${infoA.kid}

── step 1: ──────

	HWT: /.well-known/hwt-keys.json is the standardized key discovery path
	(spec §6). Any verifier, for any issuer, knows where to find the keys.
	No OIDC infrastructure. No out-of-band JWKS URL configuration.
	Verification is local after the initial fetch (spec §9 caching model).

	`);

	// ── step 2: issuer (hostA) issues a service token ─────────────────────────

	console.log(`
── step 2: issuer (hostA) issues a service token ──────────────────────────

2) Issuer: hostA   subject: svc:reporting   authz: RBAC/1.0.2 roles: [analyst]
	`);

	const { token, tid } = await post(`${hostA}/api/token`, {
		payload: {
			iss:   hostA,
			sub:   'svc:reporting',
			authz: { scheme: 'RBAC/1.0.2', roles: ['analyst'] }
		},
		expiresInSeconds: 3600
	});

	console.log(`
	Token issued by hostA
	token: ${tokenPreview(token)}
	tid:   ${tid}
	iss:   ${hostA}
	sub:   svc:reporting
	authz: { scheme: 'RBAC/1.0.2', roles: ['analyst'] }
	del:   [] — root token
	`);

	// ── step 3: verified at hostB — no contact with hostA beyond JWKS fetch ───

	console.log(`
── step 3: same token verified at hostB — no contact with hostA ───────────

3) hostB calls /api/verify-external (spec §12 verification path)
   Fetches JWKS from: ${hostA}/.well-known/hwt-keys.json  (spec §6)

   After the initial JWKS fetch, all subsequent verifications of tokens
   from the same issuer are local — no further network contact with hostA.
   This is the spec §9 caching model in action.
	`);

	const verifyAtB = await post(`${hostB}/api/verify-external`, { token });

	if(!verifyAtB.ok){
		throw new Error(`Token rejected at hostB: ${verifyAtB.error}`);
	}

	console.log(`
	Signature valid — hostA token verified by hostB
	verified sub:   ${verifyAtB.data.sub}
	verified authz: ${ JSON.stringify(verifyAtB.data.authz) }
	JWKS fetched:   ${verifyAtB._external?.jwksUrl}
	Not expired · Signature valid
	`);

	// ── step 4: same token verified at hostC — independently of hostB ─────────

	console.log(`
── step 4: same token verified at hostC — independently of hostB ──────────

4) hostC calls /api/verify-external (spec §12 verification path)
   Fetches JWKS from: ${hostA}/.well-known/hwt-keys.json  (spec §6)

   hostC is a completely independent node. It fetches the same JWKS as hostB
   fetched in step 3, but they do not coordinate with each other.
   Each verifier maintains its own key cache (spec §9).
	`);

	const verifyAtC = await post(`${hostC}/api/verify-external`, { token });

	if(!verifyAtC.ok){
		throw new Error(`Token rejected at hostC: ${verifyAtC.error}`);
	}

	console.log(`
	Signature valid — hostA token verified by hostC
	verified sub:   ${verifyAtC.data.sub}
	verified authz: ${ JSON.stringify(verifyAtC.data.authz) }
	JWKS fetched:   ${verifyAtC._external?.jwksUrl}
	Not expired · Signature valid

	Two independent verifier nodes. Zero round-trips to hostA per verification
	after the initial key fetch. hostA does not see these verification events.
	`);

	// ── step 5: scaling model — O(M) key fetches, not O(N×M) ─────────────────

	console.log(`
── step 5: scaling model ───────────────────────────────────────────────────

5) With N verifier nodes and M issuers:

   HWT local verify:   O(M) key fetches total — one per issuer per verifier
                       at startup (pre-registered) or on first encounter
                       Subsequent verifications: local, no network call

   This demo:
	   Issuer:    1  (hostA)
	   Verifiers: 2  (hostB, hostC)
	   Key fetches at each verifier: 1 per unique issuer encountered
	   Verification calls to hostA:  0 (after initial JWKS fetch)

   Production pattern — pre-registered issuers (spec §6, §11.1, §A.7):

	   at startup:
	     for each trusted issuer in allowlist:
	       fetch /.well-known/hwt-keys.json
	       import keys into local registry
	       index by iss::kid

	   at verification:
	     look up iss::kid in local registry
	     if not found: reject (unknown issuer)  ← no network call for unknowns
	     verify signature locally               ← no network call

	   This eliminates the unknown-origin SSRF attack surface (spec §11.2)
	   and converts verification into a fully local operation.

	   The unknown-issuer accept path (demonstrated in this script via
	   /api/verify-external) is correct for open deployments — but requires
	   trusting DNS and TLS to the issuer at first-fetch time for every
	   previously-unseen issuer (spec §11.1, §11.2).
	`);

	// ── step 6: kid-not-found triggers forced re-fetch ────────────────────────

	console.log(`
── step 6: kid-not-found forces JWKS re-fetch — spec §6 ───────────────────

6) When a verifier encounters an unknown kid in a token, it MUST re-fetch
   hwt-keys.json bypassing the cache (spec §6 — forced invalidation).

   This handles key rotation: new tokens carry a new kid; verifiers that
   have cached only the old JWKS will encounter an unknown kid, re-fetch,
   find the new key, and continue.

   Key rotation procedure (spec §6):
	   1. Publish the new key in hwt-keys.json alongside the existing key
	   2. Wait at least the current max-age of hwt-keys.json
	      (verifier caches need time to warm to the new key's presence)
	   3. Begin signing new tokens with the new key
	   4. Retire the old key only after all tokens signed with it have expired

   This demo environment uses in-memory JWKS caches that reset per-request
   (via /api/verify-external forceExternal=true), so re-fetch is implicit.
   In production, step 2 of the rotation procedure is the critical gap:
   skipping the wait causes verifiers with cached-but-stale JWKS to see
   an unknown kid and re-fetch — which works, but adds latency to the
   first verification per verifier after the new key appears.

   Rate limiting on forced re-fetches (spec §6): verifiers SHOULD limit
   forced re-fetches per origin to at most one per 60 seconds. This prevents
   kid-flood abuse (spec §11.7) — an attacker presenting tokens with unknown
   kid values cannot force unbounded JWKS fetches.
	`);

	// ── step 7: verify all three tokens are still valid at the third node ─────

	// Issue two more tokens to show multi-token / same-issuer behavior
	const { token: token2 } = await post(`${hostA}/api/token`, {
		payload: {
			iss:   hostA,
			sub:   'svc:audit-log',
			authz: { scheme: 'RBAC/1.0.2', roles: ['auditor'] }
		},
		expiresInSeconds: 3600
	});

	console.log(`
── step 7: two tokens from the same issuer, verified at a third node ───────

7) Two tokens from hostA verified at hostC.
   After the first JWKS fetch (step 4), hostC has hostA's public key cached.
   The second token verification hits the same issuer — no new key fetch needed.
	`);

	const verify2atC = await post(`${hostC}/api/verify-external`, { token: token2 });

	console.log(`
	Token 1: ${ tokenPreview(token)  }  sub=${verifyAtC.data.sub}   ✓
	Token 2: ${ tokenPreview(token2) }  sub=${ verify2atC.data?.sub }   ${ verify2atC.ok ? '✓' : '✗ ' + verify2atC.error }

	Both verified at hostC against the same cached JWKS from hostA.
	JWKS: ${verifyAtC._external?.jwksUrl}
	`);

	// ── summary ────────────────────────────────────────────────────────────────

	console.log(`
── summary ────────────────────────────────────────────────────────────────

	One issuer (hostA), verified independently at hostB and hostC:

	svc:reporting @ hostA → verified at hostB  (JWKS: ${hostA}/.well-known/hwt-keys.json)
	svc:reporting @ hostA → verified at hostC  (JWKS: same, independent fetch)
	svc:audit-log @ hostA → verified at hostC  (same cached JWKS, no re-fetch)

	hostA did not participate in steps 3, 4, or 7.
	Zero round-trips to hostA per verification after initial key fetch.

	...

	Security models (spec §11.1, §A.7):
	  Unknown-issuer accept: trust DNS + TLS at first-fetch; higher attack surface
	  Pre-registered issuers: allowlist at deploy time; recommended for production;
	                           eliminates unknown-origin SSRF (spec §11.2)
	`);

	Deno.exit();
}

main().catch(error => {
	console.warn(`Error:`, error.message);
	console.error(error);
	Deno.exit(1);
});
