/* run:
 *
 * deno run -A ./demo_hosts.js
 *
 * Starts hostA (:8888) and hostB (:9999) and keeps them running.
 * Streams their output to this terminal, labeled by port.
 * Exits cleanly on SIGINT / SIGTERM / SIGHUP / SIGQUIT.
 *
 * Demo scripts import ensureServers() from this file — if the hosts are
 * already running (e.g. via this runner), ensureServers() is a no-op.
 * If not, it starts them automatically and cleans up when the demo exits.
 *
 * Manual equivalents (if you prefer separate terminals):

deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8888 --hwt-keys=.hwt-keys-hosta.json
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=9999 --hwt-keys=.hwt-keys-hostb.json

deno run --allow-net --allow-run=deno ./demo-del-verify.js
 */

import { TextLineStream } from "jsr:@std/streams";

const hostA = 'http://localhost:8888';
const hostB = 'http://localhost:8889';
const hostC = 'http://localhost:8880';
const hosts = {hostA, hostB, hostC};

function get(url, all=false){
	return fetch(url)
	.then(async (res)=>{
		if(!res.ok) return Promise.reject(res);
		if(all){
			const data = await res.json();
			return {url, res, data};
		}
		return res.json();
	})
}

function post(url, body, all=false){
	return fetch(url, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body)
	})
	.then(async (res)=>{
		const data = await res.json();
		if(data.error) return Promise.reject({url, res, data, error:new Error(data.error)});
		else if(all){
			return {url, res, data};
		}
		return data;
	})
}

async function checkInstance(origin, label){
	try {
		const i = await get(`${origin}/api/info`);
		console.log(`${label} at ${origin} kid=${i.kid}`);
		return i;
	} catch {
		throw new Error(`${label} not running at ${origin} — start it first (see top of this file)`);
	}
}

export { hosts, hostA, hostB, hostC, get, post, checkInstance };

// ── readiness ────────────────────────────────────────────────────────────────

async function isReady(url){
	try {
		const res = await fetch(`${url}/api/info`);
		return res.ok;
	} catch {
		return false;
	}
}

async function waitReady(url, label, timeoutMs = 6000){
	const deadline = Date.now() + timeoutMs;
	while(Date.now() < deadline){
		if(await isReady(url)) return true;
		await new Promise(r => setTimeout(r, 200));
	}
	throw new Error(`${label} did not become ready within ${timeoutMs}ms`);
}

// ── spawn ────────────────────────────────────────────────────────────────────

const spawned = [];

function spawnServer(port, keysFile){
	const proc = new Deno.Command('deno', {
		args: [
			'run',
			'--allow-read=./',
			'--allow-write=./',
			'--allow-net=localhost',
			'./http.js',
			`--port=${port}`,
			`--hwt-keys=${keysFile}`,
		],
		stdout: 'piped',
		stderr: 'piped',
	}).spawn();

	const label = `host:${port}`;
	for(const stream of [proc.stdout, proc.stderr]){
		stream
			.pipeThrough(new TextDecoderStream())
			.pipeThrough(new TextLineStream())
			.pipeTo(new WritableStream({
				write(line){ console.log(`[${label}] ${line}`); }
			}))
			.catch(() => {});	// suppress pipe errors on exit
	}

	return proc;
}

export function killSpawned(){
	for(const proc of spawned){
		try { proc.kill('SIGTERM'); } catch { /* already gone */ }
	}
}

// ── race-safe ensureServer ───────────────────────────────────────────────────
//
// Promise cache keyed by URL — concurrent callers await the same promise
// rather than racing to spawn duplicate processes.

const _serverPromises = new Map();

function ensureServer(url, label, port, keysFile){
	if(_serverPromises.has(url)) return _serverPromises.get(url);
	const p = _startIfNeeded(url, label, port, keysFile);
	_serverPromises.set(url, p);
	return p;
}

async function _startIfNeeded(url, label, port, keysFile){
	if(await isReady(url)){
		console.log(`\t${label} already running at ${url}`);
		return;
	}
	console.log(`\tstarting ${label} on port ${port} (keys: ${keysFile})...`);
	spawned.push(spawnServer(port, keysFile));
	await waitReady(url, label);
	console.log(`${label} ready`);
}

// ── public export ────────────────────────────────────────────────────────────

export async function ensureServers(){
	console.log(`ensuring servers...`);
	const list = Object.entries(hosts).map(([name, url])=>{
		const { port } = new URL(url);
		return ensureServer(url, name, port, `.hwt-keys-${ name.toLowerCase() }.json`);
	});
	await Promise.all(list);
}

// ── signal handling ──────────────────────────────────────────────────────────

function onExit(reason){
	console.log(`exiting (${reason})`);
	killSpawned();
	Deno.exit(0);
}

Deno.addSignalListener('SIGTERM', () => onExit('SIGTERM'));
Deno.addSignalListener('SIGINT', () => onExit('SIGINT'));
Deno.addSignalListener('SIGHUP', () => onExit('SIGHUP'));
Deno.addSignalListener('SIGQUIT', () => onExit('SIGQUIT'));

// ── cli: start servers and keep running ──────────────────────────────────────

if(import.meta.main){
	await ensureServers();
	console.log(`servers ready — run demos in another terminal`);
	// keep the process alive — signal handlers above handle exit
	await new Promise(() => {});
}
