/*
HWT Baseline: Cloudflare Workers + Hono

Bare-minimum HWT issuer/verifier for Cloudflare Workers.
Handles token creation, verification, and the two required well-known endpoints.

Prerequisites:
  npm install hono hwtr           (or whatever your package names resolve to)
  wrangler secret put HWT_KEYS    (paste JSON from Hwtr.generateKeys())

HWT_KEYS format (generate once, store as secret):
  const config = await Hwtr.generateKeys({ type: 'Ed25519' });
  console.log(JSON.stringify(config));

wrangler.toml minimum:
  name = "your-service"
  main = "worker.js"
  compatibility_date = "2024-01-01"
  # HWT_KEYS declared as a secret — do not put in toml plaintext

Well-known endpoints this worker serves:
  GET /.well-known/hwt-keys.json   (spec §6 — required for cross-origin verify)
  GET /.well-known/hwt.json        (spec §7 — recommended)

Application endpoints (adapt to your needs):
  POST /token                      (create a signed token)
  POST /verify                     (verify a token — local or cross-origin)

Cross-origin verification:
  Any other HWT issuer's tokens can be verified here — the verifier fetches
  JWKS from the token's iss field. No pre-configuration required for the
  permissive path; restrict to an allowlist in production (spec §11.2).
*/

import { Hono }  from 'hono';
import { Hwtr } from 'hwtr';

// ── per-request hwtr instance (cached in module scope across requests) ────────
//
// Cloudflare Workers: env bindings are not available at module load time —
// they arrive per-request. Cache the hwtr instance after first initialization
// so key parsing happens once, not on every request.

let _hwtr  = null;
let _jwks  = null;
let _meta  = null;

async function getState(env){
	if(_hwtr) return { hwtr: _hwtr, jwks: _jwks, meta: _meta };

	if(!env.HWT_KEYS) throw new Error('HWT_KEYS secret not configured');
	const keyConfig = JSON.parse(env.HWT_KEYS);

	_hwtr = await Hwtr.factory(
		{ expiresInSeconds: 3600, maxTokenLifetimeSeconds: 0 },
		keyConfig
	);

	// Build JWKS from public keys only — never expose private key material
	_jwks = await buildJwks(keyConfig);

	// Origin is available at runtime from the request; cache the rest
	_meta = { keyConfig };

	return { hwtr: _hwtr, jwks: _jwks, meta: _meta };
}

// ── algorithm helpers ─────────────────────────────────────────────────────────

function keyTypeToImportParams(type){
	switch(type){
		case 'Ed25519':    return { importParams: { name: 'Ed25519' },                     alg: 'EdDSA' };
		case 'ECDSA-P256': return { importParams: { name: 'ECDSA', namedCurve: 'P-256' }, alg: 'ES256' };
		case 'ECDSA-P384': return { importParams: { name: 'ECDSA', namedCurve: 'P-384' }, alg: 'ES384' };
		default: throw new Error(`unsupported key type: ${type}`);
	}
}

function jwkToAlgParams(jwk){
	switch(jwk.alg){
		case 'EdDSA': return { name: 'Ed25519' };
		case 'ES256': return { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
		case 'ES384': return { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' };
		default: throw new Error(`unsupported alg: ${jwk.alg}`);
	}
}

async function buildJwks(keyConfig){
	const { importParams, alg } = keyTypeToImportParams(keyConfig.type);
	return {
		keys: await Promise.all(keyConfig.keys.map(async (entry) => {
			const spki      = base64urlToUint8Array(entry.publicKey);
			const key       = await crypto.subtle.importKey('spki', spki, importParams, true, ['verify']);
			const jwk       = await crypto.subtle.exportKey('jwk', key);
			return { ...jwk, kid: entry.id, use: 'sig', alg };
		}))
	};
}

// ── cross-origin verify (fetch remote JWKS from token's iss) ─────────────────
//
// Spec §12 steps 4–7: extract iss from payload, fetch iss/.well-known/hwt-keys.json,
// match kid, verify signature.
//
// Production recommendation: restrict accepted issuers to a pre-configured allowlist
// and reject tokens from unknown origins (spec §11.1, §11.2).

async function verifyExternal(hwtr, token){
	// decode without verification — only to extract iss for JWKS discovery
	const decoded = await hwtr.decode(token);
	const iss = decoded?.data?.iss;
	if(!iss) return { ok: false, error: 'missing iss in token payload' };

	const jwksUrl = `${iss}/.well-known/hwt-keys.json`;
	let jwks;
	try {
		const res = await fetch(jwksUrl);
		if(!res.ok) return { ok: false, error: `JWKS fetch failed (${res.status}) from ${jwksUrl}` };
		jwks = await res.json();
	} catch(err){
		return { ok: false, error: `cannot reach ${jwksUrl}: ${err.message}` };
	}

	const keys = jwks.keys ?? [];
	if(!keys.length) return { ok: false, error: `no keys at ${jwksUrl}` };

	const firstKey = keys[0];
	const params   = jwkToAlgParams(firstKey);
	const publicKeys = {};
	for(const jwk of keys){
		const cryptoKey = await crypto.subtle.importKey('jwk', jwk, params, true, ['verify']);
		publicKeys[jwk.kid] = bufferToBase64Url(await crypto.subtle.exportKey('spki', cryptoKey));
	}

	const verifier = await Hwtr.factory(
		{ expiresInSeconds: 3600, maxTokenLifetimeSeconds: 0 },
		{ current: firstKey.kid, type: keyConfig.type, keys: [], publicKeys }
	);
	const result = await verifier.verify(token);
	return { ...result, _jwksUrl: jwksUrl };
}

// Short random tid — adapt to your ID strategy
function makeTid(){
	return crypto.randomUUID().replace(/-/g,'').slice(0,12);
}

// ── routes ────────────────────────────────────────────────────────────────────

const app = new Hono();

// Spec §6 — required. Verifiers fetch this to verify tokens issued here.
app.get('/.well-known/hwt-keys.json', async (c) => {
	const { jwks } = await getState(c.env);
	return c.json(jwks);
});

// Spec §7 — recommended. Declares issuer metadata.
app.get('/.well-known/hwt.json', async (c) => {
	const origin = new URL(c.req.url).origin;
	return c.json({
		issuer:              origin,
		hwt_version:         '0.7',
		authz_schemas:       ['RBAC/1.0.2'],
		authz_evaluation:    'all',
		aud_required:        false,
		aud_array_permitted: false,
		max_delegation_depth: 10,
		endpoints: {
			token_exchange: `${origin}/token/delegate`
			// revocation: not declared — application-layer concern (spec §13)
		}
	});
});

// Create a signed token
// POST { payload: { iss, sub, authz, ... }, expiresInSeconds?: number }
// iss should be set to this worker's origin; sub and authz are caller-defined.
app.post('/token', async (c) => {
	const { hwtr } = await getState(c.env);
	const { payload, expiresInSeconds } = await c.req.json();
	if(!payload || typeof payload !== 'object') return c.json({ error: 'payload required' }, 400);
	if(!payload.tid) payload.tid = makeTid();

	const token = expiresInSeconds
		? await hwtr.createWith(Number(expiresInSeconds), payload)
		: await hwtr.create(payload);

	if(!token) return c.json({ error: 'token creation failed' }, 500);
	return c.json({ token, tid: payload.tid });
});

// Verify a token — local or cross-origin
// POST { token: "hwt...", external?: boolean }
// external: true forces cross-origin JWKS fetch even for locally-issued tokens
app.post('/verify', async (c) => {
	const { hwtr } = await getState(c.env);
	const { token, external } = await c.req.json();
	if(typeof token !== 'string') return c.json({ error: 'token must be a string' }, 400);

	const result = external
		? await verifyExternal(hwtr, token)
		: await hwtr.verify(token);

	// Application-layer state checks (e.g. revocation) go here.
	// The protocol verification above covers: signature, expiry, structure.
	// Spec §13: revocation is explicitly outside HWT protocol scope.

	return c.json(result);
});

// ── export ────────────────────────────────────────────────────────────────────

export default {
	fetch: app.fetch
};
