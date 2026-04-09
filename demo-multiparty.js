/*
HWT Demo: Multi-Party Authorization

deno run -A ./demo-multiparty.js

What this demonstrates:

Two independent organizations issue approver tokens to their own principals.
A coordinator service verifies both tokens against their respective issuers'
JWKS (spec §6, §12) — no shared identity provider, no prior agreement between
the organizations. Only when both verify does the coordinator issue a joint
authorization token using a private authz schema (spec §4.2) that records the
satisfied quorum. Any downstream service can verify the coordinator token and
inspect the approver identities from the token alone.

SCENARIO:
1. Organization A (hostA) issues an approver token to user:alice
2. Organization B (hostB) issues an approver token to user:bob
3. Coordinator (hostC) verifies both tokens cross-origin (spec §12)
4. Quorum satisfied → coordinator issues joint authorization token (private schema)
5. Downstream verifies the coordinator token — no prior knowledge of hostC
6. alice's root token revoked at hostA → coordinator token unaffected (spec §13)
*/

import { ensureServers, hostA, hostB, hostC, get, post, checkInstance } from './demo_hosts.js';
await ensureServers();

function tokenPreview(token){
	return token.length > 80 ? token.slice(0, 40) + '…' + token.slice(-20) : token;
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main(){
	console.log(`
	HWT Demo: Multi-Party Authorization

── prerequisites ──────────────────────────────────────────────────────────

0) Checking instances
	`);

	const infoA = await checkInstance(hostA, 'Organization A (hostA)');
	const infoB = await checkInstance(hostB, 'Organization B (hostB)');
	const infoC = await checkInstance(hostC, 'Coordinator    (hostC)');

	console.log(`
	Three independent services — independent key pairs, no shared secrets.
	hostA kid: ${infoA.kid}
	hostB kid: ${infoB.kid}
	hostC kid: ${infoC.kid}

── step 1: ──

	HWT: any token is verifiable against its issuer's published JWKS (spec §12).
	A coordinator can verify N tokens from N independent issuers, then issue
	its own signed attestation that the quorum was satisfied. Every layer is
	independently verifiable from the token alone — alice's token against
	hostA's JWKS, bob's against hostB's, the joint token against hostC's.
	No central service. No prior registration between the three.

	`);

	// ── step 2: organization A issues approver token to alice ─────────────────

	console.log(`
── step 2: organization A (hostA) issues approver token to user:alice ─────

2) Issuer: hostA   subject: user:alice   authz: RBAC/1.0.2 roles: [approver]
	`);

	const { token: aliceToken, tid: aliceTid } = await post(`${hostA}/api/token`, {
		payload: {
			iss:   hostA,
			sub:   'user:alice',
			authz: { scheme: 'RBAC/1.0.2', roles: ['approver'] }
		},
		expiresInSeconds: 3600
	});

	console.log(`
	Alice's token — issued by hostA
	token:  ${tokenPreview(aliceToken)}
	tid:    ${aliceTid}
	iss:    ${hostA}
	sub:    user:alice
	authz:  { scheme: 'RBAC/1.0.2', roles: ['approver'] }
	del:    [] — root token, no delegation history
	`);

	// ── step 3: organization B issues approver token to bob ───────────────────

	console.log(`
── step 3: organization B (hostB) issues approver token to user:bob ───────

3) Issuer: hostB   subject: user:bob   authz: RBAC/1.0.2 roles: [approver]
	`);

	const { token: bobToken, tid: bobTid } = await post(`${hostB}/api/token`, {
		payload: {
			iss:   hostB,
			sub:   'user:bob',
			authz: { scheme: 'RBAC/1.0.2', roles: ['approver'] }
		},
		expiresInSeconds: 3600
	});

	console.log(`
	Bob's token — issued by hostB
	token:  ${tokenPreview(bobToken)}
	tid:    ${bobTid}
	iss:    ${hostB}
	sub:    user:bob
	authz:  { scheme: 'RBAC/1.0.2', roles: ['approver'] }
	del:    [] — root token, no delegation history
	`);

	// ── step 4: coordinator verifies alice's token cross-origin ───────────────

	console.log(`
── step 4: coordinator (hostC) verifies alice's token — no prior knowledge of hostA ──

4) hostC calls /api/verify-external (spec §12 verification path)
   Fetches: ${hostA}/.well-known/hwt-keys.json  (spec §6 key discovery)
   Verifies signature locally against fetched keys — no further network call
	`);

	const aliceVerify = await post(`${hostC}/api/verify-external`, { token: aliceToken });

	if(!aliceVerify.ok){
		throw new Error(`alice's token failed verification: ${aliceVerify.error}`);
	}

	console.log(`
	Signature valid — alice's token verified by hostC
	verified sub:   ${aliceVerify.data.sub}
	verified authz: ${ JSON.stringify(aliceVerify.data.authz) }
	verified iss:   ${aliceVerify.data.iss}
	JWKS fetched:   ${aliceVerify._external?.jwksUrl}
	Not expired · Signature valid
	`);

	// ── step 5: coordinator verifies bob's token cross-origin ─────────────────

	console.log(`
── step 5: coordinator (hostC) verifies bob's token — no prior knowledge of hostB ──

5) hostC calls /api/verify-external (spec §12 verification path)
   Fetches: ${hostB}/.well-known/hwt-keys.json  (spec §6 key discovery)
	`);

	const bobVerify = await post(`${hostC}/api/verify-external`, { token: bobToken });

	if(!bobVerify.ok){
		throw new Error(`bob's token failed verification: ${bobVerify.error}`);
	}

	console.log(`
	Signature valid — bob's token verified by hostC
	verified sub:   ${bobVerify.data.sub}
	verified authz: ${ JSON.stringify(bobVerify.data.authz) }
	verified iss:   ${bobVerify.data.iss}
	JWKS fetched:   ${bobVerify._external?.jwksUrl}
	Not expired · Signature valid
	`);

	// ── step 6: quorum satisfied — coordinator issues joint auth token ─────────

	console.log(`
── step 6: quorum satisfied — coordinator issues joint authorization token ─

6) Both principals verified. hostC issues a joint auth token.

   authz uses a private schema (spec §4.2). Origin-relative scheme path
   is resolved against iss: ${hostC}/schemas/joint-approval/v1

   Private schemas require no registration (spec §4.4). The URL form is
   the unambiguous signal to any verifier that this is a private schema.

   The quorum record goes in authz — not del[]. del[] is a linear delegation
   chain tracing authorization lineage hop by hop. It has no multi-parent
   form. The coordinator is not delegating from either alice or bob; it is
   issuing its own signed attestation that the quorum was satisfied.
	`);

	const jointAuthz = {
		scheme:    '/schemas/joint-approval/v1',
		action:    'release:contract-7f2a',
		quorum:    '2-of-2',
		approvers: [
			{ iss: aliceVerify.data.iss, sub: aliceVerify.data.sub },
			{ iss: bobVerify.data.iss,   sub: bobVerify.data.sub   }
		]
	};

	const { token: jointToken, tid: jointTid } = await post(`${hostC}/api/token`, {
		payload: {
			iss:   hostC,
			sub:   'svc:coordinator',
			authz: jointAuthz
		},
		expiresInSeconds: 3600
	});

	console.log(`
	Joint authorization token — issued by hostC
	token:     ${tokenPreview(jointToken)}
	tid:       ${jointTid}
	iss:       ${hostC}
	sub:       svc:coordinator
	authz:     ${ JSON.stringify(jointAuthz) }
	           ↑ private schema — approver identities embedded in the token
	del:       [] — coordinator root, not a delegation chain
	`);

	// ── step 7: downstream verifies the coordinator token cross-origin ─────────

	console.log(`
── step 7: downstream verifies coordinator token — no prior knowledge of hostC ──

7) A downstream service (simulated here via hostA's /api/verify-external)
   Fetches: ${hostC}/.well-known/hwt-keys.json  (spec §6 key discovery)
   Verifies signature per spec §12

   The downstream inspects authz.approvers directly in the verified payload.
   hostA and hostB are not contacted at this step — the coordinator already
   did that work and signed the result into the token.
	`);

	const jointVerify = await post(`${hostA}/api/verify-external`, { token: jointToken });

	if(!jointVerify.ok){
		throw new Error(`joint auth token failed verification: ${jointVerify.error}`);
	}

	console.log(`
	Joint auth token verified by downstream
	verified sub:    ${jointVerify.data.sub}
	verified iss:    ${jointVerify.data.iss}
	verified authz:  ${ JSON.stringify(jointVerify.data.authz) }
	JWKS fetched:    ${jointVerify._external?.jwksUrl}
	approvers confirmed — no contact with hostA or hostB required
	Not expired · Signature valid
	`);

	// ── step 8: alice's root token revoked — coordinator token unaffected ──────

	console.log(`
── step 8: alice's root token revoked — coordinator token unaffected ───────

8) Simulates: alice's access withdrawn after the joint approval was issued.

   Revocation is application-layer behavior — explicitly outside the HWT
   protocol scope (spec §13). The library provides it as an opt-in extension
   via endpoints.revocation in /.well-known/hwt.json.
	`);

	await post(`${hostA}/api/revoke`, { tid: aliceTid });

	console.log(`
	Alice's root token revoked on hostA (tid: ${aliceTid})
	`);

	// Alice's root token is now rejected at hostA (local revocation check)
	const aliceRevokedCheck = await post(`${hostA}/api/verify`, { token: aliceToken })
		.catch(res => res.data);

	console.log(`
	Alice's root token at hostA: ${ aliceRevokedCheck?.ok
		? '(still valid — revocation state may not have propagated)'
		: `correctly rejected — ${ aliceRevokedCheck?.error }` }
	`);

	// The coordinator token is a separate root issued by hostC.
	// Revoking alice's token at hostA has no reach into hostC's token store.
	const jointStillValid = await post(`${hostA}/api/verify-external`, { token: jointToken })
		.catch(res => res.data);

	console.log(`
	Joint auth token (tid: ${jointTid}, iss: hostC):
	${ jointStillValid?.ok
		? `still valid — it is a root token signed by hostC, independent of alice's token at hostA`
		: `unexpected failure: ${ jointStillValid?.error }` }

	The coordinator token's signature covers the payload at issuance. Revoking
	alice's underlying token at hostA does not propagate to hostC's token store.

	To invalidate this joint auth token, the downstream revokes tid ${jointTid}
	at hostC — not alice's token at hostA. Each token's state is managed at
	its own issuer. This is deliberate: token state is outside the protocol
	(spec §13). Short token lifetimes are the primary bounding mechanism;
	application-layer revocation adds finer control when needed.
	`);

	// ── summary ────────────────────────────────────────────────────────────────

	console.log(`
── summary ────────────────────────────────────────────────────────────────

	Three independent issuers — zero pre-coordination:

	user:alice      @ hostA  verified by hostC against ${hostA}/.well-known/hwt-keys.json
	user:bob        @ hostB  verified by hostC against ${hostB}/.well-known/hwt-keys.json
	svc:coordinator @ hostC  verified by downstream against ${hostC}/.well-known/hwt-keys.json

	Each verification: fetch issuer JWKS (spec §6) → verify signature locally
	(spec §12). No central IdP. No federation agreement. No shared secrets.

	The joint auth token carries a private authz schema (spec §4.2) embedding
	both approver identities. Any downstream can inspect the quorum record
	from the token alone — without re-contacting hostA or hostB.

	authz structure note:
	  del[] is a linear delegation chain — it has no multi-parent form and
	  does not apply here. The coordinator is not delegating from alice or bob;
	  it is issuing a new signed attestation. The approver identities are
	  application data carried in authz, not protocol delegation records.

	`);

	Deno.exit();
}

main().catch(error => {
	console.warn(`Error:`, error.message);
	console.error(error);
	Deno.exit(1);
});
