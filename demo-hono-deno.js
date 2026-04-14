/*
HWT Baseline: Deno + Hono

Bare-minimum HWT issuer/verifier — Deno runtime, Hono router.
Adapt to Node/Bun/Express by substituting the runtime-specific parts
(file I/O, Deno.serve, signal handlers) — the HWT logic is identical.

deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./demo-server.js

Options:
  --port=8888           (default: 8888)
  --hwt-keys=path.json  (default: .hwt-keys.json — generated if absent)

Well-known endpoints (spec §6, §7):
  GET /.well-known/hwt-keys.json
  GET /.well-known/hwt.json

Application endpoints (adapt these to your service):
  POST /token               create a signed token
  POST /token/delegate      build a delegation chain hop
  POST /verify              verify local or cross-origin token

The delegation endpoint shows the key HWT primitive — not present in
the Cloudflare baseline because the chain pattern is runtime-agnostic.
See demo-agent-chain.js and demo-del-verify.js for the full story.
*/

function arg(name){
	const prefix = `--${name}=`;
	const found  = Deno.args.find(a => a.startsWith(prefix));
	return found ? found.slice(prefix.length) : null;
}

import { Hono }  from 'jsr:@hono/hono';
// https://jsr.io/@hwt/hwtr-js/0.1.2/hwtr.js
// jsr:@hwt/hwtr-js
import { Hwtr, base64urlToUint8Array, bufferToBase64Url } from 'jsr:@hwt/hwtr-js';

const config = {
	hostname: 'localhost',
	port:     Number(arg('port') ?? 8888),
	keyFile:  arg('hwt-keys') ?? '.hwt-keys.json',
};
config.origin = `http://${config.hostname}:${config.port}`;

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
		case 'EdDSA': return { params: { name: 'Ed25519' },                                     type: 'Ed25519'    };
		case 'ES256': return { params: { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }, type: 'ECDSA-P256' };
		case 'ES384': return { params: { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' }, type: 'ECDSA-P384' };
		default: throw new Error(`unsupported alg: ${jwk.alg}`);
	}
}

async function buildJwks(keyConfig){
	const { importParams, alg } = keyTypeToImportParams(keyConfig.type);
	return {
		keys: await Promise.all(keyConfig.keys.map(async (entry) => {
			const spki      = base64urlToUint8Array(entry.publicKey);
			const cryptoKey = await crypto.subtle.importKey('spki', spki, importParams, true, ['verify']);
			const jwk       = await crypto.subtle.exportKey('jwk', cryptoKey);
			return { ...jwk, kid: entry.id, use: 'sig', alg };
		}))
	};
}

// ── key state ─────────────────────────────────────────────────────────────────

let state = { hwtr: null, keyConfig: null, jwks: null };

async function initKeys(){
	let keyConfig = null;

	try {
		const text = await Deno.readTextFile(config.keyFile);
		keyConfig   = JSON.parse(text);
		console.log(`keys loaded  ${config.keyFile}  kid=${keyConfig.keys?.[0]?.id}`);
	} catch {
		keyConfig = await Hwtr.generateKeys({ type: 'Ed25519' });
		await Deno.writeTextFile(config.keyFile, JSON.stringify(keyConfig, null, 2));
		console.log(`keys generated + saved  ${config.keyFile}  kid=${keyConfig.keys?.[0]?.id}`);
	}

	const hwtr = await Hwtr.factory(
		{ expiresInSeconds: 3600, maxTokenLifetimeSeconds: 0 },
		keyConfig
	);

	state = { hwtr, keyConfig, jwks: await buildJwks(keyConfig) };
}

await initKeys();

console.log(`
HWT server  ${config.origin}
  ${config.origin}/.well-known/hwt.json
  ${config.origin}/.well-known/hwt-keys.json
`);

// ── cross-origin verify ───────────────────────────────────────────────────────
//
// Spec §12 steps 4–7: extract iss, fetch iss/.well-known/hwt-keys.json, verify.
// Production: restrict to a pre-configured issuer allowlist (spec §11.1, §11.2).

async function verifyAgainstIssuer(token, { forceExternal = false } = {}){
	const decoded = await state.hwtr.decode(token);
	const iss     = decoded?.data?.iss;
	if(!iss) throw new Error('missing iss in token payload');

	if(!forceExternal && iss === config.origin){
		return { result: await state.hwtr.verify(token), iss, local: true };
	}

	const jwksUrl = `${iss}/.well-known/hwt-keys.json`;
	const jwksRes = await fetch(jwksUrl);
	if(!jwksRes.ok) throw new Error(`JWKS fetch failed (${jwksRes.status}) from ${jwksUrl}`);

	const jwks    = await jwksRes.json();
	const keys    = jwks.keys ?? [];
	if(!keys.length) throw new Error(`no keys at ${jwksUrl}`);

	const { params, type } = jwkToAlgParams(keys[0]);
	const publicKeys = {};
	for(const jwk of keys){
		const cryptoKey = await crypto.subtle.importKey('jwk', jwk, params, true, ['verify']);
		publicKeys[jwk.kid] = bufferToBase64Url(await crypto.subtle.exportKey('spki', cryptoKey));
	}

	const verifier = await Hwtr.factory(
		{ expiresInSeconds: 3600, maxTokenLifetimeSeconds: 0 },
		{ current: keys[0].kid, type, keys: [], publicKeys }
	);
	return { result: await verifier.verify(token), iss, jwksUrl, local: false };
}

// ── helpers ───────────────────────────────────────────────────────────────────

function makeTid(){
	return crypto.randomUUID().replace(/-/g,'').slice(0, 12);
}

function apiErr(message, status = 500){
	return Object.assign(new Error(message), { status });
}

// ── routes ────────────────────────────────────────────────────────────────────

const app = new Hono();

// Spec §6 — required for cross-origin verification
app.get('/.well-known/hwt-keys.json', (c) => c.json(state.jwks));

// Spec §7 — recommended issuer metadata
app.get('/.well-known/hwt.json', (c) => c.json({
	issuer:              config.origin,
	hwt_version:         '0.7',
	authz_schemas:       ['RBAC/1.0.2'],
	authz_evaluation:    'all',
	aud_required:        false,
	aud_array_permitted: false,
	max_delegation_depth: 10,
	endpoints: {
		token_exchange: `${config.origin}/token/delegate`
		// revocation: not declared — application-layer concern (spec §13)
	}
}));

// Create a signed token
// POST { payload: { iss, sub, authz, ... }, expiresInSeconds?: number }
app.post('/token', async (c) => {
	const { payload, expiresInSeconds } = await c.req.json();
	if(!payload || typeof payload !== 'object') throw apiErr('payload required', 400);
	if(!payload.tid) payload.tid = makeTid();

	const token = expiresInSeconds
		? await state.hwtr.createWith(Number(expiresInSeconds), payload)
		: await state.hwtr.create(payload);

	if(!token) throw apiErr('token creation failed', 500);
	return c.json({ token, tid: payload.tid });
});

// Verify a token — local or cross-origin
// POST { token: "hwt..." }
// Returns the verified payload on success; error on failure.
// Application-layer state checks (revocation, session status) belong here,
// after protocol verification completes. Spec §13: revocation is out of scope.
app.post('/verify', async (c) => {
	const { token } = await c.req.json();
	if(typeof token !== 'string') throw apiErr('token must be a string', 400);
	const { result, iss, jwksUrl } = await verifyAgainstIssuer(token);
	return c.json({ ...result, _iss: iss, _jwksUrl: jwksUrl ?? null });
});

// Build a delegation chain hop — spec §8.1
// POST { subjectToken: "hwt...", actorSub: "svc:name", audience?: "...", expiresInSeconds?: number }
//
// Verifies the subject token against its issuer, appends a Provenance Record
// to del[], and issues a new token signed by this server.
//
// Authz attenuation (spec §8.1): derived token inherits subject token's authz.
// You can only delegate what you have, never more.
app.post('/token/delegate', async (c) => {
	const { subjectToken, actorSub, audience, expiresInSeconds } = await c.req.json();
	if(typeof subjectToken !== 'string') throw apiErr('subjectToken required', 400);

	const { result: verified } = await verifyAgainstIssuer(subjectToken);
	if(!verified.ok) throw apiErr(`subject token invalid: ${verified.error}`, 400);

	const { iss, sub, tid, del: existingDel, authz } = verified.data;

	// Provenance Record for this hop (spec §3.6)
	const newEntry = { iss, sub };
	if(tid) newEntry.tid = tid;
	const del = [...(existingDel ?? []), newEntry];

	const payload = {
		iss:   config.origin,
		sub:   actorSub || 'svc:agent',
		tid:   makeTid(),
		iat:   Math.floor(Date.now() / 1000),
		authz,	// inherited from subject token — attenuation enforced by caller
		del
	};
	if(audience) payload.aud = audience;

	const token = expiresInSeconds
		? await state.hwtr.createWith(Number(expiresInSeconds), payload)
		: await state.hwtr.create(payload);

	if(!token) throw apiErr('delegation token creation failed', 500);
	return c.json({ token, payload, chainDepth: del.length });
});

// ── error handler ─────────────────────────────────────────────────────────────

app.onError((err, c) => {
	const status = err.status ?? 500;
	return c.json({ error: err.message || 'server error' }, status);
});

// ── serve ─────────────────────────────────────────────────────────────────────

function onExit(reason){
	console.log(`exiting (${reason})`);
	Deno.exit(0);
}

Deno.addSignalListener('SIGINT',  () => onExit('SIGINT'));
Deno.addSignalListener('SIGHUP',  () => onExit('SIGHUP'));
Deno.addSignalListener('SIGTERM', () => onExit('SIGTERM'));
Deno.addSignalListener('SIGQUIT', () => onExit('SIGQUIT'));

const server = Deno.serve({ hostname: config.hostname, port: config.port }, app.fetch);
await server.finished;
