function info(){
	const kf = config.keyFile ?? '(in-memory — add --hwt-keys=filename to persist)';
	return `
simple HWT dev server — Deno 🦕 https://deno.com/

deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js

deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8888 --hwt-keys=.hwt-keys-file.json

→ in host1: create a token
→ in host2: paste into "Verify External"
pid ${ Deno.pid }
$0 ${ config.script }
cwd ${ Deno.cwd() }
origin ${ config.origin }
keyFile ${ kf }

open ${ config.origin }
${ config.origin }/.well-known/hwt.json
${ config.origin }/.well-known/hwt-keys.json
${ config.origin }/api/info
`;
}
/* ── arg parsing ─────────────────────────────────────────────────────────────
usage:
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js

deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=9999 --hwt-keys=.hwt-keys-b.json

two-instance cross-origin verify demo:
terminal hostA: deno run ... ./http.js --port=8888 --hwt-keys=.hwt-keys-a.json
terminal hostB: deno run ... ./http.js --port=9999 --hwt-keys=.hwt-keys-b.json
→ create a token on hostA, paste it into "Verify External" on hostB
*/

function arg(name){
	const prefix = `--${name}=`;
	const found = Deno.args.find(a => a.startsWith(prefix));
	return found ? found.slice(prefix.length) : null;
}

import * as paf from "jsr:@std/path";
import { serveStatic } from "jsr:@hono/hono/deno";
import { Hono } from "jsr:@hono/hono";
import { Hwtr, base64urlToUint8Array, bufferToBase64Url } from 'https://hwtprotocol.com/hwtr-js/hwtr.js';

const config = {
	hostname:  'localhost'
	,port:     Number(arg('port') ?? 8888)
	,www:      './'
	,expires:  'private, max-age=1, s-maxage=1'
	,keyFile:  arg('hwt-keys') ?? null    // null = in-memory only, no persistence
};
config.root      = paf.resolve(Deno.cwd(), config.www);
config.script    = new URL(import.meta.url).pathname;
config.origin    = `http://${config.hostname}:${config.port}`;
config.userAgent = `Deno/${Deno.version.deno} V8/${Deno.version.v8} TS/${Deno.version.typescript} ${Deno.build.target}`;


function log(status='000', VERB='GUESS', what='', who='?', client='~', where='...', other='-'){
	console.log(`${ (new Date).toISOString() } ${ status } "${ VERB } ${ what }" ${ who } "${ client }" ${ where } ${ other }`);
}

function getIP(req){
	const headers = req.raw.headers;
	return headers.get('x-forwarded-for')?.split(',')[0]?.trim()
		|| headers.get('x-real-ip')
		|| headers.get('cf-connecting-ip')
		|| '?.0.0.?';
}

function httpError(message, status=500){
	return Object.assign(new Error(message), { status });
}

// ── key state ─────────────────────────────────────────────────────────────────

let state = { hwtr: null, keyConfig: null, jwks: null };

// In-memory revocation list — cleared on server restart (intentional for dev)
// Format: [{ tid: string, at: number (unix seconds) }]
let revoked = [];

// Short random token ID — enough entropy for demo, not for production
function makeTid(){
	return crypto.randomUUID().replace(/-/g,'').slice(0, 12);
}

function isRevoked(tid){
	return tid ? revoked.some(r => r.tid === tid) : false;
}

/* 
Walk del[] and check each entry against its issuer's revocation list.
This is APPLICATION-LAYER behavior — the HWT spec (§13) explicitly places
revocation outside protocol scope. What the spec guarantees: the outer
signature covers del[] (tamper-proof chain structure). What it does NOT
define: whether any chain link's authorization has been revoked since issuance.

This library implements revocation as an opt-in extension. Issuers that
declare endpoints.revocation in /.well-known/hwt.json participate in it.
Issuers that don't are skipped (not rejected) — see check.skipped below.
*/
async function verifyDelChain(del=[]){
	const entries = [];

	for(const entry of del){
		const check = {
			iss:    entry.iss,
			sub:    entry.sub,
			tid:    entry.tid ?? null,
			revoked:   false,
			reachable: true,
			skipped:   false,
			reason:    null
		};

		if(!entry.tid){
			check.skipped = true;
			check.reason  = 'no tid — revocation check skipped (issuer did not include tid)';
			entries.push(check);
			continue;
		}

		// Local shortcut — this server is the entry's issuer
		if(entry.iss === config.origin){
			check.revoked = isRevoked(entry.tid);
			if(check.revoked){
				const e = revoked.find(r => r.tid === entry.tid);
				check.revokedAt = e?.at;
			}
			entries.push(check);
			continue;
		}

		// Remote entry — fetch issuer's hwt.json to discover the revocation endpoint
		try {
			const metaRes = await fetch(`${entry.iss}/.well-known/hwt.json`);
			if(!metaRes.ok){ throw new Error(`hwt.json returned ${metaRes.status}`); }
			const meta           = await metaRes.json();
			const revocationUrl  = meta?.endpoints?.revocation;
			check.revocationUrl  = revocationUrl ?? null;

			if(!revocationUrl){
				check.skipped = true;
				check.reason  = 'issuer declares no revocation endpoint — cannot confirm status';
				entries.push(check);
				continue;
			}

			// Fetch the revocation list and check this tid
			const revRes = await fetch(revocationUrl);
			if(!revRes.ok){ throw new Error(`revocation list returned ${revRes.status}`); }
			const revDoc     = await revRes.json();
			const revokedEntry = revDoc.revoked?.find(r => r.tid === entry.tid);
			check.revoked    = !!revokedEntry;
			if(revokedEntry) check.revokedAt = revokedEntry.at;

		} catch(err){
			// Spec §9: if revocation endpoint is declared but unreachable, MUST reject (fail-safe)
			check.reachable = false;
			check.error     = err.message;
			check.reason    = 'issuer unreachable — fail-safe: treating as unverifiable';
		}

		entries.push(check);
	}

	// Derive overall chain result
	const revokedLink     = entries.find(e => e.revoked);
	const unreachableLink = entries.find(e => !e.reachable && e.tid);

	let ok    = !revokedLink && !unreachableLink;
	let error = null;
	if(revokedLink){
		const when = revokedLink.revokedAt ? new Date(revokedLink.revokedAt*1000).toISOString() : 'unknown time';
		error = `chain link revoked: ${revokedLink.sub} @ ${revokedLink.iss} at ${when}`;
	} else if(unreachableLink){
		error = `chain link unverifiable: ${unreachableLink.iss} unreachable (fail-safe reject)`;
	}

	return { ok, error, entries };
}

// Map JWK alg → Web Crypto params + Hwtr type string
// Used in verifyAgainstIssuer when processing a fetched remote JWKS.
function jwkToAlgParams(jwk){
	switch(jwk.alg){
		case 'EdDSA': return { params: { name: 'Ed25519' },                                      type: 'Ed25519'    };
		case 'ES256': return { params: { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' },  type: 'ECDSA-P256' };
		case 'ES384': return { params: { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' },  type: 'ECDSA-P384' };
		case 'ES512': return { params: { name: 'ECDSA', namedCurve: 'P-521', hash: 'SHA-512' },  type: 'ECDSA-P521' };
		default:      throw httpError(`unsupported JWK alg: ${jwk.alg ?? '(none)'}`, 400);
	}
}

// Map Hwtr type string → Web Crypto importKey params + JWK alg string.
// Uses Hwtr.ALGORITHMS as source of truth; strips hash (not needed for
// spki/jwk key import — only for sign/verify operations).
const JWK_ALG = { 'Ed25519': 'EdDSA', 'ECDSA-P256': 'ES256', 'ECDSA-P384': 'ES384', 'ECDSA-P521': 'ES512' };

function keyTypeToImportParams(type){
	const base = Hwtr.ALGORITHMS[type];
	if(!base) throw new Error(`unsupported key type: ${type ?? '(none)'}`);
	const alg = JWK_ALG[type];
	if(!alg) throw new Error(`no JWK alg mapping for type: ${type}`);
	const { name, namedCurve } = base;
	return { importParams: namedCurve ? { name, namedCurve } : { name }, alg };
}

async function buildJwks(keyConfig){
	if(keyConfig.type === 'HMAC')
		throw new Error('HMAC keys must not be published as JWKS — cross-origin verification requires asymmetric keys (spec §2)');
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

async function initKeys(existingConfig=null){
	let keyConfig = existingConfig;

	if(!keyConfig && config.keyFile){
		try {
			const text = await Deno.readTextFile(config.keyFile);
			keyConfig   = JSON.parse(text);
			log('000', 'KEYS', `loaded ${config.keyFile} kid=${keyConfig.keys?.[0]?.id}`, '?', config.userAgent);
		} catch {
			// file missing or unreadable — fall through to generate
		}
	}

	if(!keyConfig){
		keyConfig = await Hwtr.generateKeys({ type: 'Ed25519' });
		if(config.keyFile){
			await Deno.writeTextFile(config.keyFile, JSON.stringify(keyConfig, null, 2));
			log('000', 'KEYS', `generated + saved ${config.keyFile} kid=${keyConfig.keys?.[0]?.id}`, '?', config.userAgent);
		} else {
			log('000', 'KEYS', `generated in-memory kid=${keyConfig.keys?.[0]?.id}`, '?', config.userAgent);
		}
	}

	const hwtr = await Hwtr.factory(
		{ expiresInSeconds: 3600, maxTokenLifetimeSeconds: 0 },
		keyConfig
	);

	state = { hwtr, keyConfig, jwks: keyConfig.type === 'HMAC' ? null : await buildJwks(keyConfig) };
	return state;
}

await initKeys();
console.log(info());

// ── shared: verify a token against its issuer's JWKS ─────────────────────────
// Handles both local tokens (shortcut to local hwtr) and external tokens
// (fetches JWKS from iss/.well-known/hwt-keys.json — no pre-configuration).
// forceExternal=true always goes through the discovery path (for /api/verify-external).

async function verifyAgainstIssuer(token, { forceExternal=false }={}){
	const decoded = await state.hwtr.decode(token);
	if(!decoded.data?.iss) throw httpError('cannot extract iss from token — missing iss field', 400);
	const iss = decoded.data.iss;

	// Local shortcut — skip network round-trip for tokens this server issued
	if(!forceExternal && iss === config.origin){
		return { result: await state.hwtr.verify(token), iss, jwksUrl: null, local: true, kids: [] };
	}

	const jwksUrl = `${iss}/.well-known/hwt-keys.json`;
	let jwksRes;
	try { jwksRes = await fetch(jwksUrl); }
	catch(err){ throw httpError(`cannot reach ${jwksUrl}: ${err.message}`, 502); }
	if(!jwksRes.ok) throw httpError(`JWKS fetch failed (${jwksRes.status}) from ${jwksUrl}`, 502);

	const jwks = await jwksRes.json();
	const keys  = jwks.keys ?? [];
	if(!keys.length) throw httpError(`no keys found at ${jwksUrl}`, 502);

	const firstKey              = keys[0];
	const { params, type: hwtrType } = jwkToAlgParams(firstKey);

	const publicKeys = {};
	for(const jwk of keys){
		const cryptoKey = await crypto.subtle.importKey('jwk', jwk, params, true, ['verify']);
		const spki      = await crypto.subtle.exportKey('spki', cryptoKey);
		publicKeys[jwk.kid] = bufferToBase64Url(spki);
	}

	const verifier = await Hwtr.factory(
		{ expiresInSeconds: 3600, maxTokenLifetimeSeconds: 0 },
		{ current: firstKey.kid, type: hwtrType, keys: [], publicKeys }
	);
	const result = await verifier.verify(token);
	return { result, iss, jwksUrl, local: false, kids: keys.map(k => k.kid) };
}

// ── app ───────────────────────────────────────────────────────────────────────

const app = new Hono();

app.use('*', async (c, next) => {
	const start = Date.now();
	await next();
	const time = `${ Date.now() - start }ms`;
	c.res.headers.set('X-Response-Time', time);
	c.res.headers.set('Cache-Control', config.expires);
	log(c.res.status, c.req.method, c.req.url, '?', c.req.header('user-agent') ?? '~', getIP(c.req), time);
});

// ── well-known (spec §7 §8) ───────────────────────────────────────────────────

app.get('/.well-known/hwt-keys.json', (c) => {
	if(!state.jwks || state.keyConfig?.type === 'HMAC')
		return c.json({ error: 'this issuer uses HMAC — public keys are not published (spec §2)' }, 404);
	return c.json(state.jwks);
});

app.get('/.well-known/hwt.json', (c) => {
	if(!state.jwks || state.keyConfig?.type === 'HMAC'){
		return c.json({ error: 'this issuer uses HMAC — (spec §2)' }, 404);
	};
	return c.json({
		issuer:               config.origin,
	//	hwt_version:          '0.7', // TODO
		authz_schemas:        ['RBAC/1.0.2'],
		authz_evaluation:     'all',
		aud_required:         false,
		aud_array_permitted:  false,
		max_delegation_depth: 10,
		endpoints: {
		// token_exchange is spec-defined (§7.1).
		// revocation is a library extension — not in the HWT spec.
			revocation: `${config.origin}/.well-known/hwt-revoked.json`
		}
	});
});

/* Revocation list — library extension, not defined by HWT spec.
	Declared in /.well-known/hwt.json under endpoints.revocation.
	Issuers that don't want revocation simply omit endpoints.revocation. */
app.get('/.well-known/hwt-revoked.json', (c) => {
	if(!state.jwks || state.keyConfig?.type === 'HMAC'){
		return c.json({ error: 'this issuer uses HMAC — (spec §2)' }, 404);
	};
	return c.json({
	issuer:  config.origin,
	updated: Math.floor(Date.now() / 1000),
	revoked
	});
});

// ── api — server info ─────────────────────────────────────────────────────────

app.get('/api/info', (c) => c.json({
	origin:  config.origin,
	keyFile: config.keyFile,
	kid:     state.keyConfig.keys?.[0]?.id ?? null,
	type:    state.keyConfig.type
}));

// ── api — key management ──────────────────────────────────────────────────────

// Full config including private key — dev only, do not expose in production
app.get('/api/keys', (c) => c.json(state.keyConfig));

// Regenerate keys, overwrite keyFile if configured
app.post('/api/keys/generate', async (c) => {
	await initKeys(null);
	return c.json(state.keyConfig);
});

// Restore a previously exported config (paste-from-prior-run flow)
app.post('/api/keys/import', async (c) => {
	const body = await c.req.json();
	if(!body?.keys || !Array.isArray(body.keys))
		throw httpError('invalid key config: expected { current, type, keys: [...] }', 400);
	await initKeys(body);
	return c.json(state.keyConfig);
});

// ── api — token operations ────────────────────────────────────────────────────

// Create signed token
// POST { payload: {...}, expiresInSeconds?: number }
// tid is auto-injected if absent — required since this server declares a revocation endpoint
app.post('/api/token', async (c) => {
	const { payload, expiresInSeconds } = await c.req.json();
	if(!payload || typeof payload !== 'object' || Array.isArray(payload))
		throw httpError('payload must be a JSON object', 400);
	if(!payload.tid) payload.tid = makeTid();
	const token = expiresInSeconds
		? await state.hwtr.createWith(Number(expiresInSeconds), payload)
		: await state.hwtr.create(payload);
	if(!token) throw httpError('token creation failed — check payload size', 500);
	return c.json({ token, tid: payload.tid });
});

// Verify against local keys (sig + expiry + revocation check + decode)
// POST { token: "hwt...." }
app.post('/api/verify', async (c) => {
	const { token } = await c.req.json();
	if(typeof token !== 'string') throw httpError('token must be a string', 400);
	const result = await state.hwtr.verify(token);
	// Revocation check — apply to outer token and each del chain entry
	if(result.ok && result.data){
		if(isRevoked(result.data.tid)){
			const entry = revoked.find(r => r.tid === result.data.tid);
			result.ok      = false;
			result.error   = `token revoked at ${new Date(entry.at * 1000).toISOString()}`;
			result.revoked = true;
		}
		// Surface revocation status for each chain link
		if(result.data.del?.length){
			result._delRevoked = result.data.del
				.filter(link => link.tid && isRevoked(link.tid))
				.map(link => link.tid);
			if(result.ok && result._delRevoked.length){
				result.ok    = false;
				result.error = `delegation chain contains revoked token: ${result._delRevoked[0]}`;
			}
		}
	}
	return c.json(result);
});

// Decode payload only — no signature check
// POST { token: "hwt...." }
app.post('/api/decode', async (c) => {
	const { token } = await c.req.json();
	if(typeof token !== 'string') throw httpError('token must be a string', 400);
	return c.json(await state.hwtr.decode(token));
});

// Full chain verification — the complete conformant verification algorithm:
//   1. Verify outer token signature against its issuer's JWKS
//   2. Check outer token revocation
//   3. Walk del[] — for each entry, fetch the entry's issuer's revocation list
//      and confirm the tid is not revoked (spec §3.6, §9)
//
// This is the endpoint demo-del-verify.js uses to show that:
//   · hostA revoked delegation link invalidates the chain even when the outer sig is valid
//   · Each entry's issuer is contacted independently — no central service
//
// POST { token: "hwt...." }
app.post('/api/verify-chain', async (c) => {
	const { token } = await c.req.json();
	if(typeof token !== 'string') throw httpError('token must be a string', 400);

	// Step 1 — verify outer signature against its issuer
	const { result, iss, jwksUrl } = await verifyAgainstIssuer(token);
	if(!result.ok){
		return c.json({ ok: false, error: result.error, step: 'outer_signature', data: null, chain: null });
	}

	// Step 2 — check outer token revocation
	if(isRevoked(result.data?.tid)){
		const entry = revoked.find(r => r.tid === result.data.tid);
		const when  = new Date((entry?.at ?? 0)*1000).toISOString();
		return c.json({ ok: false, error: `outer token revoked at ${when}`, step: 'outer_revocation', data: result.data, chain: null });
	}

	// Step 3 — walk del[] chain
	const del         = result.data?.del ?? [];
	const chainResult = await verifyDelChain(del);

	return c.json({
		ok:    chainResult.ok,
		error: chainResult.error ?? null,
		step:  chainResult.ok ? 'complete' : (chainResult.entries.find(e => e.revoked) ? 'del_revocation' : 'del_unreachable'),
		data:  result.data,
		chain: {
			depth:   del.length,
			entries: chainResult.entries
		},
		_verification: { iss, jwksUrl }
	});
});

// Revoke a token by tid — or extract tid from a token
// POST { tid: "..." } | { token: "hwt...." }
app.post('/api/revoke', async (c) => {
	const body = await c.req.json();
	let tid = body.tid;
	if(!tid && body.token){
		const decoded = await state.hwtr.decode(body.token);
		tid = decoded.data?.tid;
		if(!tid) throw httpError('token has no tid — include tid in the payload to enable revocation', 400);
	}
	if(!tid) throw httpError('provide tid or token', 400);
	if(!revoked.find(r => r.tid === tid)){
		revoked.push({ tid, at: Math.floor(Date.now() / 1000) });
	}
	return c.json({ revoked: true, tid, total: revoked.length });
});

// Clear the revocation list — dev convenience
app.post('/api/revoke/clear', (c) => {
	const count = revoked.length;
	revoked = [];
	return c.json({ cleared: count });
});

// Delegation chain — create a derived token from a subject token
// POST { subjectToken: "hwt...", actorSub?: "svc:agent", audience?: "...", expiresInSeconds?: number }
// Subject token may be issued by any HWT server — verifyAgainstIssuer handles cross-origin.
// Spec §3.6: del is ordered earliest-first; this token's own sub is the final delegate (not in del).
app.post('/api/token/delegate', async (c) => {
	const { subjectToken, actorSub, audience, expiresInSeconds } = await c.req.json();
	if(typeof subjectToken !== 'string') throw httpError('subjectToken must be a string', 400);

	// Verify the subject token against its issuer — works for local AND cross-origin tokens
	const { result: verified } = await verifyAgainstIssuer(subjectToken);
	if(!verified.ok) throw httpError(`subject token invalid: ${verified.error}`, 400);
	if(isRevoked(verified.data?.tid))
		throw httpError('subject token is revoked — cannot delegate from a revoked token', 400);

	const { iss, sub, tid, del: existingDel, authz } = verified.data;

	// Append this hop to the chain: existing del entries + the subject token's own identity
	const newEntry = { iss, sub };
	if(tid) newEntry.tid = tid;
	const del = [...(existingDel ?? []), newEntry];

	const payload = {
		iss:   config.origin,
		sub:   actorSub || 'svc:agent',
		tid:   makeTid(),
		iat:   Math.floor(Date.now() / 1000),
		authz: authz ?? { scheme: 'RBAC/1.0.2', roles: ['member'] },
		del
	};
	if(audience) payload.aud = audience;

	const token = expiresInSeconds
		? await state.hwtr.createWith(Number(expiresInSeconds), payload)
		: await state.hwtr.create(payload);
	if(!token) throw httpError('delegation token creation failed', 500);

	return c.json({ token, payload, chainDepth: del.length });
});

// Cross-origin verify — fetch remote JWKS from token's iss, verify there
// POST { token: "hwt...." }
// Core demo: shows any verifier can verify any issuer's tokens with no pre-configuration.
// The issuer URL is inside the token; the verifier fetches keys from iss/.well-known/hwt-keys.json.
// forceExternal=true so even locally-issued tokens exercise the discovery path for demonstration.
app.post('/api/verify-external', async (c) => {
	const { token } = await c.req.json();
	if(typeof token !== 'string') throw httpError('token must be a string', 400);

	const { result, iss, jwksUrl, kids } = await verifyAgainstIssuer(token, { forceExternal: true });

	// Apply local revocation check — full cross-origin revocation would additionally
	// fetch {iss}/.well-known/hwt-revoked.json; demo scripts show this path explicitly
	if(result.ok && result.data && isRevoked(result.data.tid)){
		const entry = revoked.find(r => r.tid === result.data.tid);
		result.ok      = false;
		result.error   = `token revoked at ${new Date(entry.at * 1000).toISOString()}`;
		result.revoked = true;
	}

	return c.json({ ...result, _external: { iss, jwksUrl, kids } });
});

// ── static file serving ───────────────────────────────────────────────────────

// Block key file from being served statically — it contains the private key
if(config.keyFile){
	const guardPath = '/' + paf.basename(config.keyFile);
	app.get(guardPath, (c) => c.text('403 Forbidden', 403));
}

app.use('*', serveStatic({ root: config.root }));

app.notFound((c) => c.text('404 Not Found', 404));

// ── error handler ─────────────────────────────────────────────────────────────
// Routes throw httpError(msg, status); this decides the wire format.
// /api/* and /.well-known/* get JSON; everything else gets HTML.

app.onError((err, c) => {
	const status = err.status ?? 500;
	const path   = new URL(c.req.url).pathname;

	const wantsJson =
		path.startsWith('/api/')
		|| path.startsWith('/.well-known/')
		|| (c.req.header('accept')       ?? '').includes('application/json')
		|| (c.req.header('content-type') ?? '').includes('application/json');

	c.res.headers.set('Cache-Control', config.expires);
	log(status, c.req.method, c.req.url, '?', c.req.header('user-agent') ?? '~', getIP(c.req));

	if(wantsJson){
		return c.json({ error: err.message || 'server error', status }, status);
	}
	return c.html(`<!doctype html><html><body>
<p>${status} ${err.message || 'server error'}</p>
</body></html>`, status);
});

// ── lifecycle ─────────────────────────────────────────────────────────────────

function exiting(){
	log('000', 'CLOSE', `http://${ config.hostname }:${ config.port }`, '?', config.userAgent);
	Deno.exit();
}

globalThis.addEventListener('beforeunload', exiting);
Deno.addSignalListener("SIGINT", exiting);
Deno.addSignalListener("SIGHUP", exiting);

log('000', 'START', `http://${ config.hostname }:${ config.port }`, '?', config.userAgent);

const _server = Deno.serve({
	hostname: config.hostname,
	port:     config.port,
}, app.fetch);

await _server.finished;
