/*
HWT Demo: HMAC — standalone

deno run ./demo-hmac.js

HMAC tokens are for single-party deployments: the same service signs
and verifies. No JWKS, no cross-origin verification. Shared secret.

Spec §2: "HMAC is valid for single-party deployments where the issuer and
verifier share a secret and cross-domain public-key verification is not
required. HMAC tokens are not conforming for the cross-domain protocol."

Good for: session tokens, internal service auth, API keys — all within
a trust boundary you control on both sides.

Not for: anything where a separate service needs to verify independently.
For that, use Ed25519 or ECDSA and the asymmetric demos.

Secret format used here — same format as the Cloudflare HMAC demo:
  {"secret":"..."} parsed as JSON, secret ≥ 32 characters.
*/

import { Hwtr, } from 'https://hwtprotocol.com/hwtr-js/hwtr.js';

/*
── config ────────────────────────────────────────────────────────────────────

In production: load this string from an environment variable or secret store.
Never commit a real secret. The format is intentionally simple so it can be
stored as a single env var string and parsed once.

Cloudflare Workers: env.HWT_SECRET
Deno:               Deno.env.get('HWT_SECRET')
Node:               process.env.HWT_SECRET

Generate a real secret:
node -e "console.log(JSON.stringify({secret: require('crypto').randomBytes(48).toString('base64url')}))"
deno eval "console.log(JSON.stringify({secret: [...crypto.getRandomValues(new Uint8Array(48))].map(b=>b.toString(16).padStart(2,'0')).join('')}))"

adjust this for your own use-case, source from : config file, environment variable, load, parsing, etc

this is pursely demonstration, not dogma

*/
const HWT_SECRET = '{"secret":"your-secret-here-minimum-32-characters"}';

function secretToKeyConfig(jsonStr){
	const { secret } = JSON.parse(jsonStr);
	if(!secret || secret.length < 32)
		throw new Error('HMAC secret must be ≥ 32 characters');
	return {
		current: 'primary',
		type:    'HMAC',
		keys: [{ id: 'primary', secret, created: new Date().toISOString() }]
	};
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main(){
	console.log(`
HWT Demo: HMAC — standalone

── step 1: create Hwtr instance from secret ───────────────────────────────
	`);

	const keyConfig = secretToKeyConfig(HWT_SECRET);
	const hwtr      = await Hwtr.factory(
		{ expiresInSeconds: 3600, maxTokenLifetimeSeconds: 0 },
		keyConfig
	);

	console.log(`
	thwtr instance ready
	type: ${keyConfig.type}  kid: ${keyConfig.keys[0].id}
	Note: no JWKS published — HMAC is single-party only (spec §2)

── step 2: create a token ─────────────────────────────────────────────────
	`);

	const payload = {
		iss:   'https://my-service.example.com',
		sub:   'user:alice',
		tid:   crypto.randomUUID().replace(/-/g,'').slice(0, 12),
		authz: { scheme: 'RBAC/1.0.2', roles: ['editor'] }
	};

	const token = await hwtr.createWith(3600, payload);

	console.log(`
	token: ${token}
	fields (dot-separated):
	`);

	const parts = token.split('.');
	console.log(`
	[0] prefix:    ${parts[0]}
	[1] signature: ${parts[1].slice(0,20)}…
	[2] kid:       ${parts[2]}
	[3] expires:   ${parts[3]} (${new Date(Number(parts[3]) * 1000).toISOString()})
	[4] format:    ${parts[4]}
	[5] payload:   ${parts[5].slice(0,30)}…
	`);

	console.log(`
── step 3: verify — correct secret ────────────────────────────────────────
	`);

	const result = await hwtr.verify(token);
	console.log(`
	ok:  ${result.ok}
	sub: ${result.data?.sub}
	iss: ${result.data?.iss}
	authz: ${JSON.stringify(result.data?.authz)}
	`);

	console.log(`
── step 4: verify — wrong secret (different instance) ─────────────────────
	`);

	const wrongConfig = secretToKeyConfig('{"secret":"completely-different-secret-value-here"}');
	const wrongHwtr   = await Hwtr.factory(
		{ expiresInSeconds: 3600, maxTokenLifetimeSeconds: 0 },
		wrongConfig
	);

	const wrongResult = await wrongHwtr.verify(token);
	console.log(`
	ok:    ${wrongResult.ok}
	error: ${wrongResult.error}
	correct — HMAC signature depends on the secret.
	a verifier with a different secret cannot validate the token.
	`);

	console.log(`
── summary ────────────────────────────────────────────────────────────────

	HMAC works for:
	- Session tokens within one service
	- Internal microservice auth (shared secret both sides)
	- API keys verified by the same service that issued them

	HMAC does NOT work for:
	- Cross-origin verification (no public key to publish)
	- Delegation chains with external verifiers
	- Anything in the AI agent delegation demos

	cross-origin and delegation: use Ed25519 or ECDSA (demo-agent-chain.js)

	`);
}

main().catch(err => { console.error(err); Deno.exit(1); });
