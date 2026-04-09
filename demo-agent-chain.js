/*
HWT Demo: AI Agent Delegation Chain

deno run -A ./demo-agent-chain.js

What this demonstrates:

An authenticated user delegates authority to an AI agent running on a
separate service. That agent further delegates to a sub-agent on a third
hop. The final token carries the full cryptographic provenance chain (del[]).
Any verifier can check every link — without contacting a central service.

SCENARIO:
1. User alice authenticates with auth server hostA → receives root token
2. Agent-1 on service hostB receives alice's token, delegates → agent token
   (iss=hostB, del=[alice@hostA])
3. Agent-2 on service hostA delegates from agent-1's token → final token
   (iss=hostA, del=[alice@hostA, agent-1@hostB])
4. Target API (hostB) verifies the final token via cross-origin discovery
5. Script revokes alice's root token — shows chain becomes invalid
*/

import { ensureServers, hostA, hostB, get, post, checkInstance } from './demo_hosts.js';
await ensureServers();

function tokenPreview(token){
	return token.length > 80 ? token.slice(0, 40) + '…' + token.slice(-20) : token;
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main(){
	console.log(`
	HWT Demo: AI Agent Delegation Chain

── prerequisites ──────────────────────────────────────────────────────────

0) Checking instances
	`);
	const infoA = await checkInstance(hostA, 'Auth server (hostA)');
	const infoB = await checkInstance(hostB, 'Agent service (hostB)');

	console.log(`
	hostA and hostB have independent keys — no shared secrets, no prior agreement
	hostA kid: ${infoA.kid}  hostB kid: ${infoB.kid}

	HWT encodes the full chain inside the token. The outer signature covers
	del[] — tamper-proof provenance without a central coordinator.
	That's what steps 2–4 below demonstrate.

	`);

	// ── step 1: root user token ────────────────────────────────────────────────

	console.log(`
── step 1: user alice authenticates with hostA → root token ───────────────

1) Root token issued by auth server
   iss=hostA  sub=user:alice  del=[]
	`);

	const { token: userToken, tid: userTid } = await post(`${hostA}/api/token`, {
		payload: {
			iss:   hostA,
			sub:   'user:alice',
			authz: { scheme: 'RBAC/1.0.2', roles: ['editor'] }
		},
		expiresInSeconds: 3600
	});

	console.log(`
	Root token issued by hostA
	token: ${tokenPreview(userToken)}
	tid:   ${userTid}
	iss:   ${hostA}
	sub:   user:alice
	authz: { scheme: 'RBAC/1.0.2', roles: ['editor'] }
	del:   [] — root token has no delegation history
	`);

	// ── step 2: agent-1 on hostB delegates from alice's token ─────────────────

	console.log(`
── step 2: agent-1 on hostB delegates alice's token (cross-server) ────────

2) hostB calls /api/token/delegate
   Verifies alice's token against hostA's JWKS first:
   Fetches: ${hostA}/.well-known/hwt-keys.json
	`);

	const { token: agent1Token, payload: agent1Payload, chainDepth: depth1 } = await post(`${hostB}/api/token/delegate`, {
		subjectToken:     userToken,
		actorSub:         'svc:agent-1',
		audience:         'https://api.target.example.com',
		expiresInSeconds: 3600
	});

	const agent1Tid = agent1Payload?.tid;

	console.log(`
	Agent-1 token issued by hostB (chain depth: ${depth1})
	token: ${tokenPreview(agent1Token)}
	iss:   ${hostB}
	sub:   svc:agent-1
	tid:   ${agent1Tid}
	authz: ${ JSON.stringify(agent1Payload?.authz) }
	       ↑ inherited from alice's token (spec §8.1 — you can only delegate what you have)
	del[0]: ${ JSON.stringify(agent1Payload?.del?.[0]) }
	         ↑ alice@hostA — independently verifiable against hostA's published keys
	aud:   https://api.target.example.com
	`);

	// ── step 3: agent-2 on hostA delegates from agent-1's token ───────────────

	console.log(`
── step 3: agent-2 on hostA delegates agent-1's token (extends chain) ─────

3) hostA calls /api/token/delegate
   Verifies agent-1's token against hostB's JWKS first:
   Fetches: ${hostB}/.well-known/hwt-keys.json

   audience omitted here — agent-2 issues a broader token not bound to a
   single target (valid; aud is optional per spec §3.2).
	`);

	const { token: agent2Token, payload: agent2Payload, chainDepth: depth2 } = await post(`${hostA}/api/token/delegate`, {
		subjectToken:     agent1Token,
		actorSub:         'svc:agent-2',
		expiresInSeconds: 3600
	});

	const agent2Tid = agent2Payload?.tid;

	// del[] grows with each hop. The outer signature covers the entire array —
	// a verifier can confirm the chain was not tampered with after issuance.
	console.log(`
	Agent-2 token issued by hostA (chain depth: ${depth2})
	token: ${tokenPreview(agent2Token)}
	iss:   ${hostA}
	sub:   svc:agent-2
	tid:   ${agent2Tid}
	authz: ${ JSON.stringify(agent2Payload?.authz) }
	       ↑ still editor — cannot be escalated through delegation
	del[0]: ${ JSON.stringify(agent2Payload?.del?.[0]) }
	del[1]: ${ JSON.stringify(agent2Payload?.del?.[1]) }
	         ↑ del[0]=alice@hostA  del[1]=agent-1@hostB
	           full provenance, covered by this token's signature
	`);

	// ── step 4: target API verifies the final token cross-origin ──────────────

	console.log(`
── step 4: target API (hostB) verifies final token — no prior knowledge of hostA ──

4) hostB fetches ${hostA}/.well-known/hwt-keys.json at verify time
	`);

	const verifyResult = await post(`${hostB}/api/verify-external`, { token: agent2Token });

	if(verifyResult.ok){
		console.log(`
	Signature valid — outer token verified against hostA's JWKS
	del[] array integrity guaranteed by the outer signature
	Not expired · Not revoked
	verified sub: ${verifyResult.data.sub}
	del chain:    ${ JSON.stringify(verifyResult.data.del) }
	JWKS fetched: ${verifyResult._external?.jwksUrl ?? hostA + '/.well-known/hwt-keys.json'}
		`);
	} else {
		console.warn(`Verification failed: ${verifyResult.error}`);
	}

	// ── step 5: full delegation chain ─────────────────────────────────────────

	console.log(`
── step 5: full delegation chain ──────────────────────────────────────────

5) Provenance record carried in the token itself
	`);

	const chain = [
		...(agent2Payload.del ?? []),
		{ iss: agent2Payload.iss, sub: agent2Payload.sub, tid: agent2Payload.tid, _final: true }
	];

	chain.forEach((hop, i) => {
		const label = hop._final ? `[final] ${hop.sub}` : `[${i}]     ${hop.sub}`;
		console.log(`\t${label}\n\tiss: ${hop.iss}${ hop.tid ? `\n\ttid: ${hop.tid}` : '' }${ !hop._final ? '\n\t↓ delegated to\n' : '' }`);
	});

	// ── step 6: revoke alice's token — chain becomes invalid ──────────────────

	console.log(`
── step 6: revoke alice's root token — chain becomes invalid ──────────────

6) Revoking tid: ${userTid} on auth server hostA
   Simulates: account suspension, permission withdrawal, session termination
	`);

	await post(`${hostA}/api/revoke`, { tid: userTid });
	console.log(`
	Token revoked on hostA
	`);

	// /api/verify checks local revocation only — it's the protocol verification.
	// Cross-origin del[] revocation is application-layer behavior (spec §13),
	// demonstrated in demo-del-verify.js.
	const revokedCheck = await post(`${hostA}/api/verify`, { token: agent2Token })
		.catch(res => res.data);

	if(!revokedCheck.ok && revokedCheck.error?.includes('revoked')){
		console.log(`
	hostA correctly rejects agent-2 token — del chain contains revoked tid
	error: ${revokedCheck.error}
		`);
	} else if(revokedCheck.ok){
		console.log(`
	Note: /api/verify checks local revocation only.
	Cross-origin del[] revocation — where hostB fetches hostA's revocation list
	to catch alice's revocation — is application-layer behavior (spec §13).
	See demo-del-verify.js for the explicit cross-origin revocation demonstration.
		`);
	}

	// ── summary ────────────────────────────────────────────────────────────────

	console.log(`
── summary ────────────────────────────────────────────────────────────────

	Chain built:
	user:alice  @ hostA (tid: ${userTid})
	 ↓ delegated to
	svc:agent-1 @ hostB (tid: ${agent1Tid})
	 ↓ delegated to
	svc:agent-2 @ hostA (tid: ${agent2Tid}) ← outer token

	Each hop:
	- verified the prior token against its issuer's published JWKS
	- inherited authz unchanged (spec §8.1 — attenuation, never escalation)
	- appended a Provenance Record to del[]
	- signed the full chain into the new token

	The final token is self-describing — any verifier with network access
	can reconstruct the full chain from the token alone. No central service.
	`);

	Deno.exit();
}

main().catch(error => {
	console.warn(`Error:`, error.message);
	console.error(error);
	Deno.exit(1);
});
