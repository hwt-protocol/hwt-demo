/*
HWT Demo: Revocation Strategies

deno run -A ./demo-revocation-strategies.js

What this demonstrates:

HWT is a stateless protocol. Token state — including revocation — is explicitly
outside the protocol scope (spec §13). This is a deliberate design boundary:
narrowing scope produces more precise security claims and clearer integrator
responsibility. The protocol defines what a signed token structurally guarantees.
What happens after issuance is the application's job.

This demo addresses the most common practical question an adopter has:

  "When should I shorten the token lifetime vs build a revocation system?"

Two strategies exist. A third is a hybrid. The choice depends on your exposure
window requirement, your operational budget for revocation infrastructure, and
your availability tolerance. This demo shows all three with concrete examples.

STRATEGY 1 — Short-lived tokens (primary mechanism, spec §1 §2 §A.1):
  Tokens expire naturally. No infrastructure beyond the token itself.
  Primary security control for bounding token exposure.
  Cost: clients must re-authenticate frequently.

STRATEGY 2 — Long-lived tokens + explicit revocation (application-layer):
  Tokens have extended lifetimes. A revocation list enables immediate
  invalidation. Infrastructure cost: the revocation list must be maintained,
  distributed, and checked on every verification.
  This library implements revocation as an opt-in extension (spec §13).
  Cost: infrastructure, operational complexity, availability dependency.

STRATEGY 3 — Hybrid (moderate lifetime + revocation for edge cases):
  Moderate token lifetime limits the revocation list size and check frequency.
  Revocation handles the cases where natural expiry is too slow.
  The practical default for most production systems.

SCENARIO:
1. Strategy 1: issue a 5-second token, verify, wait for expiry, verify again
2. Strategy 2: issue a 1-hour token, revoke immediately, verify → rejected
3. Strategy 3: issue a 15-minute token, revoke only if needed
4. Decision matrix: which strategy for which deployment context
*/

import { ensureServers, hostA, post, checkInstance } from './demo_hosts.js';
await ensureServers();

function tokenPreview(token){
	return token.length > 80 ? token.slice(0, 40) + '…' + token.slice(-20) : token;
}

function sleep(ms){
	return new Promise(r => setTimeout(r, ms));
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main(){
	console.log(`
	HWT Demo: Revocation Strategies

── setup ──────────────────────────────────────────────────────────────────

0) Checking instance
	`);

	await checkInstance(hostA, 'Auth server (hostA)');

	console.log(`
	The fundamental question:
	  "If this token is compromised or a user's access is withdrawn,
	   how long can an attacker use it?"

	That interval is your exposure window. The right strategy depends
	on what exposure window is acceptable for your deployment.

── what the protocol guarantees ───────────────────────────────────────────

	HWT structural guarantees (spec §1, §2, §12):
	  · Token was signed by the issuer — signature verification (spec §12 step 7)
	  · Token has not expired — structural expiry field (spec §2, §12 step 2)
	  · Delegation chain was not tampered with — outer sig covers del[] (spec §3.5)

	What the protocol does NOT guarantee (spec §13):
	  · Whether a token has been invalidated after issuance
	  · Whether a user's permissions have changed
	  · Whether a session is still active
	  · Any of this is state that lives outside the signed byte string

	"HWT intentionally does not address it. Applications that need immediate
	invalidation maintain their own state store and check it in the application
	layer. Short token lifetimes are the primary mechanism for bounding exposure."
	— spec §1

	`);

	// ── strategy 1: short-lived tokens ────────────────────────────────────────

	console.log(`
── strategy 1: short-lived tokens — no infrastructure needed ──────────────

	Token lifetime IS the revocation. When a token expires, it becomes
	unconditionally invalid (spec §2) — no infrastructure, no state store,
	no network call. The exposure window equals the token lifetime.

	Tradeoff: clients must re-authenticate when the token expires.
	For most API contexts this is transparent (background refresh).
	For user-facing sessions, 15-30 minute token lifetimes with refresh
	are common (spec §A.1: "General API — 1-4 hours; Financial API — 5-15 min").

	Issuing a short-lived token (5 seconds) and watching it expire...
	`);

	const { token: shortToken, tid: shortTid } = await post(`${hostA}/api/token`, {
		payload: {
			iss:   hostA,
			sub:   'user:alice',
			authz: { scheme: 'RBAC/1.0.2', roles: ['member'] }
		},
		expiresInSeconds: 5
	});

	console.log(`
	Short-lived token issued
	token:   ${tokenPreview(shortToken)}
	tid:     ${shortTid}
	expires: in 5 seconds
	authz:   { scheme: 'RBAC/1.0.2', roles: ['member'] }
	`);

	// Verify immediately — should succeed
	const shortVerifyOk = await post(`${hostA}/api/verify`, { token: shortToken })
		.catch(res => res.data);

	console.log(`	Verify immediately:  ${ shortVerifyOk.ok ? 'VALID ✓' : 'INVALID: ' + shortVerifyOk.error }`);

	// Wait for expiry
	console.log(`\n\tWaiting 6 seconds for token to expire...\n`);
	await sleep(6000);

	// Verify after expiry — should fail
	const shortVerifyExpired = await post(`${hostA}/api/verify`, { token: shortToken })
		.catch(res => res.data);

	console.log(`	Verify after expiry: ${ shortVerifyExpired.ok ? 'VALID (unexpected)' : 'INVALID ✓ — ' + shortVerifyExpired.error }

	Natural expiry. Zero infrastructure. The token is its own revocation.
	No revocation list. No network call. No state store.

	When to use this exclusively:
	  · Exposure window of minutes to hours is acceptable
	  · Re-authentication cost is low (background refresh token flow)
	  · Infrastructure budget is limited
	  · Stateless architecture is a hard requirement
	`);

	// ── strategy 2: long-lived tokens + explicit revocation ───────────────────

	console.log(`
── strategy 2: long-lived tokens + explicit revocation ────────────────────

	Long token lifetimes reduce re-authentication friction. Explicit revocation
	handles the cases where natural expiry is too slow: account suspension,
	permission withdrawal, session termination on logout, key compromise.

	Revocation infrastructure:
	  · Issuer maintains a revocation list (library extension — spec §13)
	  · List is published at endpoints.revocation in /.well-known/hwt.json
	  · Verifiers fetch and check the list per-verification (or cache it)
	  · If the revocation endpoint is declared but unreachable: fail-safe reject

	Cost: the revocation endpoint is on the verification critical path.
	If it is unavailable, verifiers that declared it must fail-safe reject
	(matching the behavior of JWT introspection outages — same failure mode,
	same operational requirement).

	Issuing a 1-hour token and revoking it immediately...
	`);

	const { token: longToken, tid: longTid } = await post(`${hostA}/api/token`, {
		payload: {
			iss:   hostA,
			sub:   'user:bob',
			authz: { scheme: 'RBAC/1.0.2', roles: ['editor'] }
		},
		expiresInSeconds: 3600
	});

	console.log(`
	Long-lived token issued
	token:   ${tokenPreview(longToken)}
	tid:     ${longTid}
	expires: in 3600 seconds (1 hour)
	authz:   { scheme: 'RBAC/1.0.2', roles: ['editor'] }
	`);

	// Verify before revocation — should succeed
	const longVerifyOk = await post(`${hostA}/api/verify`, { token: longToken })
		.catch(res => res.data);

	console.log(`	Verify before revocation: ${ longVerifyOk.ok ? 'VALID ✓' : 'INVALID: ' + longVerifyOk.error }`);

	// Revoke — application-layer operation, spec §13
	await post(`${hostA}/api/revoke`, { tid: longTid });

	console.log(`\n\tToken revoked (tid: ${longTid}) — application-layer operation (spec §13)\n`);

	// Verify after revocation — should fail
	const longVerifyRevoked = await post(`${hostA}/api/verify`, { token: longToken })
		.catch(res => res.data);

	console.log(`	Verify after revocation:  ${ longVerifyRevoked.ok ? 'VALID (unexpected)' : 'INVALID ✓ — ' + longVerifyRevoked.error }

	Immediate invalidation — token has 59+ minutes of lifetime remaining
	but is rejected at the application layer. The signature is still
	cryptographically valid; the revocation check is what catches it.

	When to use explicit revocation:
	  · Exposure window must be seconds (logout, account suspension)
	  · Long token lifetimes required (user experience, background agents)
	  · Revocation endpoint availability can be guaranteed
	  · Revocation list size is manageable (prune expired entries regularly)
	`);

	// ── strategy 3: hybrid ────────────────────────────────────────────────────

	console.log(`
── strategy 3: hybrid — moderate lifetime + revocation for edge cases ──────

	Moderate token lifetime (15-30 minutes for user sessions, up to 24 hours
	for internal services per spec §A.1) covers the normal case. Revocation
	handles the edge cases where natural expiry is too slow.

	This limits the revocation list to only the tokens that actually needed
	early invalidation — the common case (expiry) requires no infrastructure.
	The revocation list stays small and cacheable.

	Issuing a 15-minute token — typical general API lifetime (spec §A.1)...
	`);

	const { token: hybridToken, tid: hybridTid } = await post(`${hostA}/api/token`, {
		payload: {
			iss:   hostA,
			sub:   'user:carol',
			authz: { scheme: 'RBAC/1.0.2', roles: ['member'] }
		},
		expiresInSeconds: 900   // 15 minutes
	});

	// Verify the hybrid token — valid now
	const hybridVerify = await post(`${hostA}/api/verify`, { token: hybridToken })
		.catch(res => res.data);

	console.log(`
	15-minute token issued (tid: ${hybridTid})
	Verify immediately: ${ hybridVerify.ok ? 'VALID ✓' : 'INVALID: ' + hybridVerify.error }

	Normal case: token expires naturally in 15 minutes. No revocation needed.
	The exposure window is at most 15 minutes even if the token is compromised.

	Edge case (account suspension): revoke immediately — same as strategy 2.
	  await post(\`\${hostA}/api/revoke\`, { tid: '${hybridTid}' })
	  Exposure window drops to seconds.
	`);

	// ── decision matrix ───────────────────────────────────────────────────────

	console.log(`
── decision matrix ────────────────────────────────────────────────────────

	Context                       │ Recommended strategy   │ Lifetime
	──────────────────────────────┼────────────────────────┼──────────────
	Financial / payment API       │ Short-lived only       │ 5–15 min
	General user session          │ Hybrid (short + revoke)│ 15–60 min
	General API (background svc)  │ Hybrid or short-lived  │ 1–4 hours
	Internal service-to-service   │ Short-lived sufficient │ Up to 24 hr
	Long-lived agent delegation   │ Must use revocation    │ Up to 7 days
	Offline / intermittent access │ Short-lived only       │ App-defined

	(Lifetime ranges from spec §A.1)

	Key questions to answer for your deployment:

	  1. What is the maximum acceptable exposure window?
	     If minutes are acceptable → short-lived tokens may be sufficient.
	     If seconds are required → revocation infrastructure is necessary.

	  2. What is the re-authentication cost for your clients?
	     Transparent background refresh → short lifetimes are cheap.
	     Visible re-authentication → longer lifetimes reduce friction.

	  3. Can you guarantee revocation endpoint availability?
	     Fail-safe reject means revocation endpoint downtime = verification
	     failures. If you can not guarantee availability, prefer short lifetimes.

	  4. What is your revocation list management plan?
	     Revocation lists grow over time. Entries for expired tokens should be
	     pruned. An unbounded revocation list degrades check performance.

── revocation in this library ─────────────────────────────────────────────

	This library implements revocation as an opt-in extension (spec §13):
	  · endpoints.revocation in /.well-known/hwt.json declares participation
	  · /.well-known/hwt-revoked.json publishes the revocation list
	  · /api/verify checks this server's local revocation list
	  · /api/verify-chain walks del[] and checks each entry's issuer's list
	  · /api/revoke adds a tid to this server's list

	Issuers that do not declare endpoints.revocation are not checked —
	they are skipped with a note, not failed (see demo-del-verify.js).

	Carrying a claim is not compliance. A token with a tid enables revocation
	only if the issuer implements and declares a revocation endpoint.
	Including tid is RECOMMENDED for auditability (spec §3.2) regardless of
	whether revocation is active.

	`);

	// ── summary ────────────────────────────────────────────────────────────────

	console.log(`
── summary ────────────────────────────────────────────────────────────────

	Strategy 1 — Short-lived (5s demo, 5–60 min production):
	  Token expired naturally in step 1. Zero infrastructure.
	  Exposure window = token lifetime. Primary mechanism (spec §1).

	Strategy 2 — Explicit revocation (1h token revoked immediately):
	  Token had 59+ minutes remaining. Rejected in seconds.
	  Infrastructure cost: revocation endpoint + availability guarantee.

	Strategy 3 — Hybrid (15 min token, revoke only when needed):
	  Common case uses natural expiry. Edge cases use revocation.
	  Revocation list stays small. Operationally the most practical default.

	The spec position (spec §1, §13):
	  "Short token lifetimes are the primary mechanism for bounding exposure.
	   Applications that need immediate invalidation maintain their own state
	   store and check it in the application layer."

	Revocation is not a patch for long token lifetimes — it is a complement
	to a well-chosen lifetime. Start with the lifetime. Add revocation only
	when the lifetime alone cannot meet your exposure window requirement.

	`);

	Deno.exit();
}

main().catch(error => {
	console.warn(`Error:`, error.message);
	console.error(error);
	Deno.exit(1);
});
