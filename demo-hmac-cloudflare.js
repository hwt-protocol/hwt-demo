/*
HWT HMAC: Cloudflare Workers + Hono

HMAC token issuer/verifier for Cloudflare Workers.
Single-party deployment — same worker signs and verifies.
No JWKS endpoint. No cross-origin verification.

Spec §2: HMAC tokens are not conforming for the cross-domain protocol.
Use the asymmetric demo (demo-cloudflare.js) for anything that needs
external verification or delegation chains.

Prerequisites:
  npm install hono hwtr
  wrangler secret put HWT_SECRET

HWT_SECRET format — a JSON string with a single key:
  {"secret":"your-secret-here-minimum-32-characters"}

Generate one:
  node -e "console.log(JSON.stringify({secret:require('crypto').randomBytes(48).toString('base64url')}))"

In local development (.dev.vars or .env depending on wrangler version):
  HWT_SECRET={"secret":"change-this-before-any-real-use-ok"}

Endpoints:
  POST /token     create a signed token
  POST /verify    verify a token (local only — HMAC is single-party)

No /.well-known/hwt-keys.json — HMAC public keys are not published.
/.well-known/hwt.json is served for metadata (no key discovery endpoint).
*/

import { Hono } from 'hono';
import { Hwtr } from 'hwtr';

// ── build keyConfig from the HWT_SECRET env var ───────────────────────────────
//
// HWT_SECRET is a JSON string: {"secret":"..."}
// Parsed once on first request, cached for the worker's lifetime.

function secretToKeyConfig(jsonStr){
	const { secret } = JSON.parse(jsonStr);
	if(!secret || secret.length < 32)
		throw new Error('HWT_SECRET.secret must be ≥ 32 characters');
	return {
		current: 'primary',
		type:    'HMAC',
		keys: [{ id: 'primary', secret, created: new Date().toISOString() }]
	};
}

// ── per-worker state — cached after first init ────────────────────────────────

let _state = null;

async function getState(env){
	if(_state) return _state;
	if(!env.HWT_SECRET) throw new Error('HWT_SECRET secret not configured');

	const keyConfig = secretToKeyConfig(env.HWT_SECRET);
	const hwtr      = await Hwtr.factory(
		{ expiresInSeconds: 3600, maxTokenLifetimeSeconds: 0 },
		keyConfig
	);
	_state = { hwtr };
	return _state;
}

// ── helpers ───────────────────────────────────────────────────────────────────

function makeTid(){
	return crypto.randomUUID().replace(/-/g,'').slice(0, 12);
}

// ── routes ────────────────────────────────────────────────────────────────────

const app = new Hono();

// Spec §7 — metadata without key discovery (HMAC keys are not published)
app.get('/.well-known/hwt.json', async (c) => {
	const origin = new URL(c.req.url).origin;
	return c.json({
		issuer:              origin,
		hwt_version:         '0.7',
		authz_schemas:       ['RBAC/1.0.2'],
		authz_evaluation:    'all',
		aud_required:        false,
		aud_array_permitted: false,
		// delegation requires asymmetric keys (omitted max_delegation_depth)
		// no endpoints.token_exchange — HMAC cannot support cross-origin delegation
	});
});

// No /.well-known/hwt-keys.json — HMAC keys are never published (spec §2)
app.get('/.well-known/hwt-keys.json', (c) =>
	c.json({ error: 'this issuer uses HMAC — public keys are not published (spec §2)' }, 404)
);

// Create a signed token
// POST { payload: { iss, sub, authz, ... }, expiresInSeconds?: number }
app.post('/token', async (c) => {
	const { hwtr } = await getState(c.env);
	const { payload, expiresInSeconds } = await c.req.json();
	if(!payload || typeof payload !== 'object')
		return c.json({ error: 'payload required' }, 400);
	if(!payload.tid) payload.tid = makeTid();

	const token = expiresInSeconds
		? await hwtr.createWith(Number(expiresInSeconds), payload)
		: await hwtr.create(payload);

	if(!token) return c.json({ error: 'token creation failed' }, 500);
	return c.json({ token, tid: payload.tid });
});

// Verify a token — local only
// POST { token: "hwt..." }
//
// HMAC verification is local: the same secret that signed must verify.
// Cross-origin verification is not possible with HMAC — use the
// asymmetric worker (demo-cloudflare.js) if you need that.
app.post('/verify', async (c) => {
	const { hwtr } = await getState(c.env);
	const { token } = await c.req.json();
	if(typeof token !== 'string')
		return c.json({ error: 'token must be a string' }, 400);

	const result = await hwtr.verify(token);

	// Application-layer state checks (session validity, revocation) go here.
	// Spec §13: revocation is outside HWT protocol scope.

	return c.json(result);
});

// ── export ────────────────────────────────────────────────────────────────────

export default {
	fetch: app.fetch
};
