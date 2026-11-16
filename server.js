// Proof Gatekeeper agent — zkVerify Agent Games Season 01.
// Single Node.js HTTP server (no framework, plain `http`).
//   POST /gatekeeper  — signed task envelopes (Proof Gatekeeper)
//   GET  /health      — readiness (HMAC configured? self-test? seen-set size?)
//   GET  /           — info
//
// Every inbound request is HMAC-verified over the RAW body against
// `x-agent-games-signature` BEFORE parsing (when AGENT_GAMES_HMAC_SECRET is
// set). Every response is signed the same way. Preflight
// {"type":"agent-games.preflight.v1"} is answered {ok:true, protocolVersion:"v1"}.
//
// Fail closed: REJECT on any uncertainty, missing field, or proof failure.
// Retries of the same task_id return the IDENTICAL cached response
// (same proof — the salt is generated once per task_id, not per request).
// A proof_tx seen under a DIFFERENT task_id is PROOF_REUSED (no proof).
//
// No wallet, no keys, no spending — game endpoint only.
const fs = require('fs');
const path = require('path');
const http = require('http');

(function loadEnv() {
  const envFile = path.join(__dirname, '.env');
  try {
    for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch { /* no .env — env vars only */ }
})();

const { verifySignature, signatureFor } = require('./shared/hmac');
const { verifyLocally } = require('./shared/snark');
const { decide, seenProofTx } = require('./gatekeeper/decide');
const { proveTask } = require('./gatekeeper/prove');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex'; // or 'sha256='
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak';

// task_id -> full response body (identical replay on platform retry)
const responseCache = new Map();

let selfTest = 'pending';

function sendJson(res, status, obj, sign) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (sign && HMAC_SECRET) headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, body, HMAC_FORMAT);
  res.writeHead(status, headers);
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function verifyInbound(rawBody, req) {
  if (!HMAC_SECRET) {
    console.warn('[warn] AGENT_GAMES_HMAC_SECRET is not set — inbound HMAC is NOT verified. Set it before going live.');
    return true;
  }
  const sig = req.headers['x-agent-games-signature'];
  return verifySignature(HMAC_SECRET, rawBody, sig, HMAC_FORMAT);
}

function isPreflight(obj) {
  return obj && obj.type === 'agent-games.preflight.v1';
}

async function handleGatekeeper(obj) {
  // The official envelope is NESTED: task_id at the top level, the decision
  // fields under `input`. A flat envelope (fields at top level) is also
  // accepted. task_id MUST come from the envelope top level — `input` does
  // not carry it — otherwise the response cache and the PROOF_REUSED
  // seen-set both silently break (every task would look like task_id '').
  const task = Object.assign({}, obj.input || obj);
  if (!task.task_id && obj.task_id) task.task_id = obj.task_id;
  const taskId = String(task.task_id || '');

  // Idempotency: platform retry of the same task_id returns the IDENTICAL response.
  if (taskId && responseCache.has(taskId)) {
    return { status: 200, body: responseCache.get(taskId), cached: true };
  }

  const required = ['registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block', 'current_block', 'recipient', 'condition_recipient', 'amount', 'max_transfer'];
  for (const f of required) {
    if (task[f] === undefined || task[f] === null || task[f] === '') {
      const body = { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: String(task.proof_tx || '') };
      if (taskId) responseCache.set(taskId, body);
      return { status: 200, body };
    }
  }

  const { decision, reason_code } = decide(task);
  const proofTx = String(task.proof_tx || '');

  if (reason_code === 'PROOF_REUSED') {
    // No proof to submit for a reused proof (platform excludes these from the reliability bonus).
    const body = { decision, reason_code, proof_tx: proofTx };
    if (taskId) responseCache.set(taskId, body);
    return { status: 200, body };
  }

  try {
    const { proof, publicSignals } = await proveTask(task, decision, TASK_ID_MODE);
    const body = { decision, reason_code, proof_tx: proofTx, proof, public_signals: publicSignals };
    if (taskId) responseCache.set(taskId, body);
    return { status: 200, body };
  } catch (e) {
    // Circuit refused the decision (should not happen — decide() mirrors the
    // circuit). Fail closed: return the decision WITHOUT a proof.
    console.error('[gatekeeper] proof generation failed (decision still returned):', e.message);
    const body = { decision, reason_code, proof_tx: proofTx };
    if (taskId) responseCache.set(taskId, body);
    return { status: 200, body };
  }
}

async function selfTests() {
  try {
    const task = {
      task_id: 'gk_selftest_1',
      registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      minimum: '1000', public_balance: '1460', expiry_block: '8430000', current_block: '8420000',
      recipient: '0x1111111111111111111111111111111111111111',
      condition_recipient: '0x1111111111111111111111111111111111111111',
      amount: '500', max_transfer: '1000', proof_tx: '0xselftest',
    };
    const { decision } = decide(task);
    const { proof, publicSignals } = await proveTask(task, decision, TASK_ID_MODE);
    const ok = await verifyLocally('gatekeeper', publicSignals, proof);
    selfTest = ok && decision === 'APPROVE' ? 'PASS (APPROVE proof verifies locally)' : 'FAIL';
  } catch (e) {
    selfTest = 'FAIL: ' + e.message;
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return sendJson(res, 200, {
        ok: true,
        service: 'proof-gatekeeper',
        hmacConfigured: !!HMAC_SECRET,
        taskIdMode: TASK_ID_MODE,
        selfTest,
        seenProofTx: seenProofTx.size,
        cachedResponses: responseCache.size,
        uptimeSec: Math.floor(process.uptime()),
      });
    }
    if (req.method === 'GET' && req.url === '/') {
      return sendJson(res, 200, {
        service: 'agent-games-proof-gatekeeper',
        handle: 'garredcrypto',
        endpoints: ['POST /gatekeeper', 'GET /health'],
      });
    }
    if (req.method !== 'POST' || req.url !== '/gatekeeper') {
      return sendJson(res, 404, { error: 'not found' });
    }
    const rawBody = await readBody(req);
    if (!verifyInbound(rawBody, req)) {
      console.warn('[warn] HMAC mismatch on /gatekeeper');
      return sendJson(res, 401, { error: 'bad signature' });
    }
    let obj;
    try {
      obj = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return sendJson(res, 400, { error: 'invalid JSON' });
    }
    if (isPreflight(obj)) {
      return sendJson(res, 200, { ok: true, protocolVersion: 'v1' }, true);
    }
    const result = await handleGatekeeper(obj);
    if (result.cached) console.log(`[gatekeeper] task ${obj.input?.task_id || obj.task_id} — replayed cached response`);
    return sendJson(res, result.status, result.body, true);
  } catch (e) {
    console.error('[server] unhandled error:', e);
    return sendJson(res, 500, { error: 'internal error' });
  }
});

server.listen(PORT, HOST, async () => {
  console.log(`[server] listening on ${HOST}:${PORT}  (POST /gatekeeper, GET /health)`);
  console.log(`[server] HMAC secret: ${HMAC_SECRET ? 'configured' : 'NOT SET (inbound verification disabled)'}`);
  console.log(`[server] taskIdMode: ${TASK_ID_MODE}`);
  await selfTests();
  console.log(`[server] self-test: ${selfTest}`);
});
