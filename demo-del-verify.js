/*
HWT Demo: Full Delegation Chain Verification

deno run -A ./demo-del-verify.js

What this demonstrates:

The critical security property that makes delegation chains meaningful:
a token whose outer signature is valid can still be invalid if any link
in its del[] chain has been revoked.

When a user delegates to an agent, and the user's access is later revoked
(account suspended, permission withdrawn, session terminated), the agent's
derived token must also become invalid — even though nobody re-signed it
and its own signature is still cryptographically correct.

HWT protocol (spec §12) covers:
  - Outer token signature verification against issuer's JWKS
  - Expiry check
  - del[] structural integrity (covered by outer signature)

This library adds application-layer revocation checking (spec §13 explicitly
places revocation outside protocol scope):
  - Each del entry's issuer is fetched independently for revocation status
  - No central service — each issuer's own list is the authority

The key moment:
Step 5 — outer signature still valid. Application-layer check fails.
The protocol said valid. The application layer says invalid.
These are distinct outcomes — spec §12 explicitly separates them.
*/

import { ensureServers, hostA, hostB, get, post, checkInstance } from './demo_hosts.js';
await ensureServers();

// ── print a chain entry with clear status ─────────────────────────────────────

function printChainEntry(entry, index, total){
	const isLast = index === total - 1;
	const status = entry.revoked     ? 'REVOKED'
		: !entry.reachable             ? 'UNREACHABLE — fail-safe reject'
		: entry.skipped                ? 'skipped (no tid)'
		: 'ok';

	console.log(`\n\t${ isLast ? '[final delegate]' : `[del ${index}]` }  ${status}`);
	console.log(`\tiss: ${entry.iss}`);
	console.log(`\tsub: ${entry.sub}`);
	if(entry.tid)           console.log(`\ttid: ${entry.tid}`);
	if(entry.revocationUrl) console.log(`\trevocation checked: ${entry.revocationUrl}`);
	if(entry.reason)        console.log(`\tnote: ${entry.reason}`);
	if(entry.revokedAt)     console.log(`\trevoked at: ${ new Date(entry.revokedAt * 1000).toISOString() }`);
	if(entry.error)         console.log(`\terror: ${entry.error}`);
	if(!isLast)             console.log(`\t↓`);
}

// ── run a verify-chain call and print full results ────────────────────────────

async function runChainVerify(label, targetServer, token){
	console.log(`
	${ label }
	Calling: ${targetServer}/api/verify-chain
	Verifier has no prior configuration for any issuer in this chain
	`);

	const res  = await fetch(`${targetServer}/api/verify-chain`, {
		method:  'POST',
		headers: { 'Content-Type': 'application/json' },
		body:    JSON.stringify({ token })
	});
	const data = await res.json();

	// Outer signature failed — nothing else to check
	if(data.step === 'outer_signature'){
		console.warn(`\tOuter signature invalid: ${data.error}`);
		return data;
	}
	if(data.step === 'outer_revocation'){
		console.warn(`\tOuter token revoked: ${data.error}`);
		return data;
	}

	console.log(`
	Outer signature valid ✓
	Verified against: ${data._verification?.jwksUrl ?? data._verification?.iss + '/.well-known/hwt-keys.json'}
	`);

	// Print each chain entry using printChainEntry
	const delEntries  = data.chain?.entries ?? [];
	const outerEntry  = {
		iss:      data.data?.iss,
		sub:      data.data?.sub,
		tid:      data.data?.tid,
		revoked:  false,
		reachable: true,
		skipped:  false
	};
	const allEntries = [...delEntries, outerEntry];

	console.log(`\tChain (${delEntries.length} delegation ${delEntries.length === 1 ? 'hop' : 'hops'} + final delegate):`);
	allEntries.forEach((entry, i) => printChainEntry(entry, i, allEntries.length));

	if(data.ok){
		console.log(`\n\tChain VALID — all ${delEntries.length} delegation ${delEntries.length === 1 ? 'link' : 'links'} verified\n`);
	} else {
		console.log(`\n\tChain INVALID — ${data.error}`);
		console.log(`\tfailed at step: ${data.step}\n`);
	}

	return data;
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main(){
	console.log(`
	HWT Demo: Full Delegation Chain Verification

── prerequisites ──────────────────────────────────────────────────────────

0) Checking instances
	`);
	await checkInstance(hostA, 'Auth server (hostA)');
	await checkInstance(hostB, 'Agent service (hostB)');

	console.log(`
── step 1: build a 2-hop delegation chain ─────────────────────────────────

1) Build a 2-hop cross-server delegation chain
   user:alice @ hostA → svc:agent-1 @ hostB → svc:agent-2 @ hostA
	`);

	// Root token: alice on hostA
	const { token: aliceToken, tid: aliceTid } = await post(`${hostA}/api/token`, {
		payload: {
			iss:   hostA,
			sub:   'user:alice',
			authz: { scheme: 'RBAC/1.0.2', roles: ['editor'] }
		},
		expiresInSeconds: 3600
	});
	console.log(`\tRoot token:    user:alice  @ hostA  tid=${aliceTid}`);

	// Agent-1 on hostB delegates alice's token
	const { token: agent1Token, tid: agent1Tid } = await post(`${hostB}/api/token/delegate`, {
		subjectToken:     aliceToken,
		actorSub:         'svc:agent-1',
		expiresInSeconds: 3600
	}).then(r => ({ token: r.token, tid: r.payload?.tid }));
	console.log(`\tAgent-1 token: svc:agent-1 @ hostB  tid=${agent1Tid}  del depth=1`);

	// Agent-2 on hostA delegates agent-1's token
	const { token: agent2Token, payload: agent2Payload } = await post(`${hostA}/api/token/delegate`, {
		subjectToken:     agent1Token,
		actorSub:         'svc:agent-2',
		expiresInSeconds: 3600
	});
	const agent2Tid = agent2Payload?.tid;
	console.log(`\tAgent-2 token: svc:agent-2 @ hostA  tid=${agent2Tid}  del depth=2`);

	console.log(`
	del[0]: ${ JSON.stringify(agent2Payload?.del?.[0]) }
	del[1]: ${ JSON.stringify(agent2Payload?.del?.[1]) }

	del[] is covered by agent-2's outer signature — cannot be tampered with after issuance.
	This is what the spec means by "each link is independently verifiable":
	the outer signature guarantees the chain structure; verifiers then check
	application-layer state (revocation) for each link independently.
	`);

	console.log(`
── step 2: protocol verification — all valid ──────────────────────────────

2) Protocol verification (sig + expiry + del[] structural check)
   This is the complete HWT verification algorithm per spec §12.
	`);

	const result1 = await runChainVerify(
		'Protocol + revocation check on hostB (no prior issuer config)',
		hostB, agent2Token
	);
	if(!result1.ok){
		console.log(`\n Unexpected failure — check instances are running`);
		Deno.exit(1);
	}

	console.log(`
── step 3: protocol verification alone — and why it's not sufficient alone ──

3) /api/verify-external — protocol verification only (sig + expiry)
   This correctly verifies the outer token per spec §12.
   It does NOT walk del[] for revocation — that's application-layer state.
   Used alone, it cannot detect a revoked chain link.
	`);

	const outerOnly = await post(`${hostB}/api/verify-external`, { token: agent2Token });
	if(outerOnly.ok){
		console.log(`
	Protocol verification: PASSED ✓
	Signature valid · Not expired · del[] structure intact
	This is correct — the outer signature IS valid.

	The gap: a token can be protocol-valid but application-invalid
	if a chain link's authorization has been revoked since issuance.
	Spec §13 places revocation outside protocol scope — it is the
	application's responsibility to check it.
		`);
	}

	console.log(`
── step 4: revoke alice's root authorization on hostA ─────────────────────

4) Revoke alice's root authorization — user:alice has been suspended
   This represents: account suspension, permission withdrawal, session termination.
   Revoking tid: ${aliceTid} on hostA
	`);

	await post(`${hostA}/api/revoke`, { tid: aliceTid });
	console.log(`\talice's token revoked — now in ${hostA}/.well-known/hwt-revoked.json`);

	const revokedDoc = await get(`${hostA}/.well-known/hwt-revoked.json`);
	const aliceInList = revokedDoc.revoked?.some(r => r.tid === aliceTid);
	console.log(`\tConfirmed in revocation list: tid=${aliceTid} present=${aliceInList}`);

	console.log(`
── step 5: the key moment ─────────────────────────────────────────────────

5) THE KEY MOMENT

   agent-2's token was NOT re-signed. Its outer signature is still
   cryptographically correct. But alice's delegation is now revoked.
   The chain is broken at del[0].

   The protocol says: valid.
   The application layer says: invalid.
   Spec §12 explicitly separates these as distinct outcomes.
	`);

	// Protocol verification still passes — as it should
	const outerAfterRevoke = await post(`${hostB}/api/verify-external`, { token: agent2Token });
	if(outerAfterRevoke.ok){
		console.log(`
	Protocol verification: still PASSES ✓
	(signature valid, not expired — the protocol is correct to pass this)

	This is NOT a protocol failure. The outer sig is valid.
	What changed is application-layer state — alice's revocation record.
	A verifier that only runs protocol verification cannot see this.
		`);
	}

	// Application-layer revocation check now fails
	const result2 = await runChainVerify('Protocol + revocation check after alice revocation', hostB, agent2Token);

	if(!result2.ok && result2.step === 'del_revocation'){
		console.log(`
	Correctly rejected at application layer.
	del[0] (alice) is revoked — fetched ${hostA}/.well-known/hwt-revoked.json → found tid=${aliceTid}
	agent-2's token is invalid despite having a valid outer signature.
		`);
	}

	console.log(`
── step 6: agent-1's own token also rejected ──────────────────────────────

6) Revocation propagates up the chain
   alice's revocation means agent-1 was also acting without valid authority.
	`);

	const agent1ChainVerify = await fetch(`${hostB}/api/verify-chain`, {
		method:  'POST',
		headers: { 'Content-Type': 'application/json' },
		body:    JSON.stringify({ token: agent1Token })
	}).then(r => r.json());

	if(!agent1ChainVerify.ok){
		console.log(`
	agent-1's token also rejected: ${agent1ChainVerify.error}
	del[0] = alice@hostA — same revoked link
		`);
	}

	console.log(`
── summary ────────────────────────────────────────────────────────────────

	Chain built:
	user:alice  @ hostA (tid: ${aliceTid})
	 ↓ delegated to
	svc:agent-1 @ hostB (tid: ${agent1Tid})
	 ↓ delegated to
	svc:agent-2 @ hostA (tid: ${agent2Tid}) ← outer token

	After alice was revoked:

	Protocol verification /api/verify-external
	  PASSED ✓ — sig valid, expiry valid, del[] structure intact
	  Correct. The spec says this passes. The outer signature is valid.

	Protocol + application-layer revocation /api/verify-chain
	  ✓ Outer sig valid
	  ✗ del[0] revocation check FAILED — alice's tid in hostA's revocation list
	  → Token rejected

	Revocation check path for del[0]:
	  1. Read del[0].iss → ${hostA}
	  2. Fetch ${hostA}/.well-known/hwt.json → find endpoints.revocation
	  3. Fetch revocation list → check tid=${aliceTid} → found → reject

	No central service. Each issuer's revocation list is fetched independently.
	Any verifier implementing this application-layer check reaches the same
	conclusion from the token alone.

	Note: revocation checking is a library feature layered on top of HWT,
	not a protocol requirement. Spec §13 explicitly places revocation outside
	protocol scope. The protocol defines the chain structure and signature
	guarantee. What you do with it — including revocation — is yours to decide.
	`);

	Deno.exit();
}

main().catch(error => {
	console.warn(`Error:`, error.message);
	console.error(error);
	Deno.exit(1);
});
