/*
HWT Demo: Service Mesh Delegation Chain

deno run -A ./demo-mesh.js

What this demonstrates:

A request flows through a three-service mesh. Each service delegates to the
next, building a del[] chain that captures the full authorization lineage.
The final token carries independently-verifiable provenance for every hop —
without a central mesh authority.

Key spec properties shown:
  del[] grows with each hop — earliest principal first (spec §3.5)
  authz is inherited unchanged at every hop — spec §8.1 (attenuation, never escalation)
  The outer signature covers the full del[] array — tamper-proof provenance (spec §3.5)
  Depth limit applies: verifiers enforce max_delegation_depth (spec §3.5, §11.8)

SCENARIO:
1. user:alice authenticates with hostA → root token (role: viewer)
2. svc:gateway on hostB delegates from alice's token
   del=[alice@hostA], chainDepth=1
3. svc:backend on hostC delegates from gateway's token
   del=[alice@hostA, gateway@hostB], chainDepth=2
4. Target API (hostA) verifies the final token cross-origin (spec §12 steps 11–13)
5. authz traced through the chain — role never escalated (spec §8.1)
6. alice's root token revoked — chain becomes invalid at hostA
*/

import { ensureServers, hostA, hostB, hostC, get, post, checkInstance } from './demo_hosts.js';
await ensureServers();

function tokenPreview(token){
	return token.length > 80 ? token.slice(0, 40) + '…' + token.slice(-20) : token;
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main(){
	console.log(`
	HWT Demo: Service Mesh Delegation Chain

── prerequisites ──────────────────────────────────────────────────────────

0) Checking instances
	`);

	const infoA = await checkInstance(hostA, 'Auth / Target (hostA)');
	const infoB = await checkInstance(hostB, 'Gateway       (hostB)');
	const infoC = await checkInstance(hostC, 'Backend       (hostC)');

	console.log(`
	Three mesh services — independent key pairs, no shared mesh CA.
	hostA kid: ${infoA.kid}  hostB kid: ${infoB.kid}  hostC kid: ${infoC.kid}

── step 1: service mesh ───────

	HWT: each service uses its own key pair — no mesh CA required. The
	delegation chain is inside the final token. The outer signature covers
	the full del[] array (spec §3.5): any verifier can confirm the chain
	was not tampered with after the last hop. One token, one signature,
	full provenance.

	`);

	// ── step 2: root token for user:alice ─────────────────────────────────────

	console.log(`
── step 2: user:alice authenticates with hostA → root token ───────────────

2) Root token issued by auth server hostA
   iss=hostA  sub=user:alice  authz: RBAC/1.0.2 roles: [viewer]  del=[]
	`);

	const { token: aliceToken, tid: aliceTid } = await post(`${hostA}/api/token`, {
		payload: {
			iss:   hostA,
			sub:   'user:alice',
			authz: { scheme: 'RBAC/1.0.2', roles: ['viewer'] }
		},
		expiresInSeconds: 3600
	});

	console.log(`
	Root token issued by hostA
	token: ${tokenPreview(aliceToken)}
	tid:   ${aliceTid}
	iss:   ${hostA}
	sub:   user:alice
	authz: { scheme: 'RBAC/1.0.2', roles: ['viewer'] }
	       ↑ viewer role — cannot be escalated through delegation (spec §8.1)
	del:   [] — root token, no delegation history
	`);

	// ── step 3: gateway (hostB) delegates from alice's token ──────────────────

	console.log(`
── step 3: svc:gateway on hostB delegates alice's token ───────────────────

3) hostB calls /api/token/delegate
   Verifies alice's token against hostA's JWKS first:
   Fetches: ${hostA}/.well-known/hwt-keys.json  (spec §6)
	`);

	const { token: gatewayToken, payload: gatewayPayload, chainDepth: depth1 } = await post(`${hostB}/api/token/delegate`, {
		subjectToken:     aliceToken,
		actorSub:         'svc:gateway',
		expiresInSeconds: 3600
	});

	const gatewayTid = gatewayPayload?.tid;

	console.log(`
	Gateway token issued by hostB (chain depth: ${depth1})
	token: ${tokenPreview(gatewayToken)}
	tid:   ${gatewayTid}
	iss:   ${hostB}
	sub:   svc:gateway
	authz: ${ JSON.stringify(gatewayPayload?.authz) }
	       ↑ inherited from alice's token — spec §8.1: you can only delegate what you have
	del[0]: ${ JSON.stringify(gatewayPayload?.del?.[0]) }
	         ↑ alice@hostA — spec §3.5: earliest principal first
	`);

	// ── step 4: backend (hostC) delegates from gateway's token ────────────────

	console.log(`
── step 4: svc:backend on hostC delegates gateway's token ─────────────────

4) hostC calls /api/token/delegate
   Verifies gateway's token against hostB's JWKS first:
   Fetches: ${hostB}/.well-known/hwt-keys.json  (spec §6)

   del[] grows: existing entries from gateway token + gateway's own identity
   appended as a Provenance Record (spec §3.5, §8.1)
	`);

	const { token: backendToken, payload: backendPayload, chainDepth: depth2 } = await post(`${hostC}/api/token/delegate`, {
		subjectToken:     gatewayToken,
		actorSub:         'svc:backend',
		expiresInSeconds: 3600
	});

	const backendTid = backendPayload?.tid;

	console.log(`
	Backend token issued by hostC (chain depth: ${depth2})
	token: ${tokenPreview(backendToken)}
	tid:   ${backendTid}
	iss:   ${hostC}
	sub:   svc:backend
	authz: ${ JSON.stringify(backendPayload?.authz) }
	       ↑ still viewer — authz was not and cannot be escalated
	del[0]: ${ JSON.stringify(backendPayload?.del?.[0]) }
	del[1]: ${ JSON.stringify(backendPayload?.del?.[1]) }
	         ↑ del[0]=alice@hostA  del[1]=svc:gateway@hostB
	           full provenance, covered by this token's outer signature
	`);

	// ── step 5: target API verifies the final token cross-origin ──────────────

	console.log(`
── step 5: target API (hostA) verifies final token — cross-origin ─────────

5) hostA calls /api/verify-external (spec §12 verification path)
   Fetches: ${hostC}/.well-known/hwt-keys.json  (spec §6 — hostC is the outer issuer)

   spec §12 delegation chain verification (steps 11–13):
   Step 11: confirm del[] depth ≤ max_delegation_depth (${depth2} ≤ 10) ✓
   Step 12: for each del entry — confirm iss is a valid HTTPS URL, sub is present
            Outer signature guarantees contents were not tampered with after issuance
   Step 13: delegation chain structurally valid
	`);

	const targetVerify = await post(`${hostA}/api/verify-external`, { token: backendToken });

	if(!targetVerify.ok){
		throw new Error(`Final token rejected by target: ${targetVerify.error}`);
	}

	console.log(`
	Signature valid — backend token verified by target (hostA)
	verified sub:  ${targetVerify.data.sub}
	verified authz: ${ JSON.stringify(targetVerify.data.authz) }
	verified iss:  ${targetVerify.data.iss}
	JWKS fetched:  ${targetVerify._external?.jwksUrl}
	del depth:     ${targetVerify.data.del?.length ?? 0} (within limit)
	Not expired · Signature valid · Chain structurally valid
	`);

	// ── step 6: authz trace — role unchanged through every hop ────────────────

	console.log(`
── step 6: authz trace — spec §8.1 attenuation across the chain ───────────

6) Authorization at every hop:

	user:alice     (hostA): ${ JSON.stringify(aliceToken ? { scheme: 'RBAC/1.0.2', roles: ['viewer'] } : null) }  ← root grant
	svc:gateway    (hostB): ${ JSON.stringify(gatewayPayload?.authz) }
	svc:backend    (hostC): ${ JSON.stringify(backendPayload?.authz) }
	target sees:            ${ JSON.stringify(targetVerify.data?.authz) }

   spec §8.1: "The derived token's authz MUST be equal to or a strict subset
   of the subject token's authz for each schema present. The constructing
   entity MUST NOT issue a derived token claiming permissions not present
   in the subject token. You can only delegate what you have, never more."

   viewer → viewer → viewer. The role does not change because the
   delegation endpoint copies the subject's authz unchanged. Any attempt
   to issue a derived token claiming broader permissions than the subject
   token would violate the normative chain construction rules (spec §8.1).
	`);

	// ── step 7: revoke alice's root token — chain becomes invalid ─────────────

	console.log(`
── step 7: revoke alice's root token — chain becomes invalid ──────────────

7) Revoking tid: ${aliceTid} on auth server hostA
   Revocation is application-layer behavior (spec §13 — explicitly out of scope).
   The library implements it as an opt-in extension via endpoints.revocation.
	`);

	await post(`${hostA}/api/revoke`, { tid: aliceTid });

	console.log(`
	Alice's root token revoked on hostA
	`);

	// /api/verify checks local revocation (library extension).
	// This catches chain links whose issuer is this server.
	const revokedCheck = await post(`${hostA}/api/verify`, { token: backendToken })
		.catch(res => res.data);

	if(!revokedCheck.ok && revokedCheck.error){
		console.log(`
	hostA correctly rejects backend token — del chain contains revoked tid
	error: ${revokedCheck.error}

	Note: this revocation check is local to hostA. Full cross-origin del[]
	revocation — where hostA fetches each remote issuer's revocation list —
	is a separate library extension demonstrated in demo-del-verify.js.
	The outer signature is cryptographically valid; the chain link is invalid
	by application-layer state (spec §13).
		`);
	} else {
		console.log(`
	/api/verify checks local revocation only.
	Cross-origin del[] revocation is demonstrated in demo-del-verify.js.
		`);
	}

	// ── summary ────────────────────────────────────────────────────────────────

	console.log(`
── summary ────────────────────────────────────────────────────────────────

	Chain built across three independent services:

	user:alice   @ hostA  (tid: ${aliceTid})   ← root
	 ↓ delegated to
	svc:gateway  @ hostB  (tid: ${gatewayTid})
	 ↓ delegated to
	svc:backend  @ hostC  (tid: ${backendTid}) ← outer token

	Each hop:
	  · verified the prior token against its issuer's published JWKS (spec §6)
	  · inherited authz unchanged (spec §8.1 — attenuation, never escalation)
	  · appended a Provenance Record to del[] (spec §3.5)
	  · signed the full chain into the new token

	The final token is self-describing — any verifier with network access
	can reconstruct the full chain from the token alone. No mesh CA.
	No central authority. No shared secrets between the three services.

	...

	SPIFFE / SVID comparison:

	  Mesh CA required for SVIDs   → HWT: each service uses its own key pair
	  Delegation chain in mTLS     → HWT: del[] in the token itself (spec §3.5)
	  Multi-artifact provenance    → HWT: one token, one outer signature, full chain
	  CA compromise = all services → HWT: per-service key compromise is isolated

	`);

	Deno.exit();
}

main().catch(error => {
	console.warn(`Error:`, error.message);
	console.error(error);
	Deno.exit(1);
});
