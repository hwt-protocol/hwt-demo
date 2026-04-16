import Hwtr from 'jsr:@hwt/hwtr-js'
/*
deno run ./demo-basic.js
 */

const KID = 'demo-example';
const ISS = 'https://example.com';
const LIFETIME = 60 * 60 * 24 * 30;
// generate a fresh Ed25519 key pair
const keyConfig = await Hwtr.generateKeys({
	type: 'Ed25519',
	current: KID,
});
const hwtr = await Hwtr.factory({
	expiresInSeconds: LIFETIME,
	maxTokenLifetimeSeconds: LIFETIME,
}, keyConfig);
// demo token
const token = await hwtr.create({
	iss: ISS,
	sub: 'demo:user',
	authz: { scheme: 'RBAC/1.0.2', roles: ['user'] },
});
if (!token) {
	throw new Error('token creation failed')
}
// export public key as SPKI base64url, then convert to JWK for the well-known endpoint
const publicKeys = await hwtr.getPublicKeys();
// { 'demo-example': '<base64url SPKI>' }
const spkiBase64 = publicKeys[KID];
const spkiBuffer = Hwtr.base64urlToUint8Array(spkiBase64);
const cryptoKey = await crypto.subtle.importKey(
	'spki',
	spkiBuffer,
	{ name: 'Ed25519' },
	true,
	['verify'],
);
const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);
const jwks = {
	keys: [
		{
			kty: jwk.kty,    // 'OKP'
			kid: KID,
			use: 'sig',
			alg: 'EdDSA',
			crv: jwk.crv,    // 'Ed25519'
			x: jwk.x,        // base64url raw public key
		},
	],
}
// verify the token round-trips correctly before printing
const verifier = await Hwtr.factory({}, {
	type: 'Ed25519',
	keys: [],
	publicKeys: { [KID]: spkiBase64 },
})
const check = await verifier.verify(token)
const hwtConfig = {
	issuer:              ISS,
	hwt_version:         '0.7',
	authz_schemas:       ['RBAC/1.0.2'],
};
console.log(`
demo-example...
`,
	`
token ${ check.ok ? 'verified':`invalid ${ check.error }` }, expires: ${ new Date(check.expires * 1000).toISOString() }
	`,
	 JSON.stringify({token}),
	`

/.well-known/hwt-keys.json`, JSON.stringify(jwks, null, '\t'),
	`

/.well-known/hwt.json`, JSON.stringify(hwtConfig, null, '\t'),
	`

PRIVATE key config (store securely)`, JSON.stringify(keyConfig, null, '\t'),

`

NOTE can add keys into existing config array to continue using all.
`
);
if (!check.ok) {
	console.warn(`verification failed`, check);
}
