// End-to-end live test of the gatekeeper server over HTTP.
// Starts the server on a test port with a test HMAC secret, then exercises:
//   /health, preflight (good + bad signature), valid task, trap task,
//   same-task retry (identical response), PROOF_REUSED, unsigned request.
// Every returned proof is verified locally against the registered VK.
// Run: node test-live.js
const { spawn } = require('child_process');
const crypto = require('crypto');
const http = require('http');

const PORT = 18081;
const SECRET = 'test-secret-0123456789abcdef0123456789abcdef';
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR = '0x1111111111111111111111111111111111111111';
const OTHER = '0x2222222222222222222222222222222222222222';

function hmac(secret, body) {
  return crypto.createHmac('sha256', secret).update(body).digest('hex');
}

function req(method, path, bodyObj, sign) {
  return new Promise((resolve, reject) => {
    const body = bodyObj === undefined ? '' : (typeof bodyObj === 'string' ? bodyObj : JSON.stringify(bodyObj));
    const headers = { 'Content-Type': 'application/json' };
    if (sign) headers['x-agent-games-signature'] = hmac(SECRET, body);
    const r = http.request({ host: '127.0.0.1', port: PORT, path, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

function verifyRespSig(resp) {
  const sig = resp.headers['x-agent-games-signature'];
  if (!sig) return false;
  return sig === hmac(SECRET, resp.body);
}

async function main() {
  const server = spawn('node', ['server.js'], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  server.stdout.on('data', (d) => { out += d.toString(); });
  server.stderr.on('data', (d) => { out += d.toString(); });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // wait for self-test
  let ready = false;
  for (let i = 0; i < 40; i++) {
    await sleep(500);
    if (out.includes('self-test:')) { ready = true; break; }
  }
  if (!ready) { console.log('SERVER DID NOT START\n' + out); server.kill(); process.exit(1); }
  console.log(out.trim().split('\n').map((l) => '  [server] ' + l).join('\n'));

  const { createRequire } = require('module');
  // snarkjs verify needs the module from this dir
  const snarkjs = require('snarkjs');
  const vk = await snarkjs.zKey.exportVerificationKey(require('path').join(__dirname, 'circuits', 'gatekeeper_final.zkey'));

  let pass = 0, total = 0;
  const check = (name, ok, extra = '') => {
    total++;
    if (ok) pass++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
  };

  // 1. /health
  const h = await req('GET', '/health');
  const hj = JSON.parse(h.body);
  check('/health 200 + self-test PASS', h.status === 200 && hj.selfTest.startsWith('PASS'), `selfTest=${hj.selfTest}`);

  // 2. preflight (signed)
  const pf = { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' };
  const pfr = await req('POST', '/gatekeeper', pf, true);
  const pfj = JSON.parse(pfr.body);
  check('preflight signed -> {ok:true, protocolVersion:v1}', pfr.status === 200 && pfj.ok === true && pfj.protocolVersion === 'v1');
  check('preflight response is HMAC-signed', verifyRespSig(pfr));

  // 3. preflight with BAD signature -> 401
  const bad = await req('POST', '/gatekeeper', pf, false);
  // send with a wrong signature manually
  const bad2 = await new Promise((resolve, reject) => {
    const body = JSON.stringify(pf);
    const r = http.request({ host: '127.0.0.1', port: PORT, path: '/gatekeeper', method: 'POST', headers: { 'Content-Type': 'application/json', 'x-agent-games-signature': 'deadbeef' } }, (res) => {
      const c = []; res.on('data', (x) => c.push(x)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(c).toString() }));
    });
    r.on('error', reject); r.write(body); r.end();
  });
  check('preflight with wrong HMAC -> 401', bad2.status === 401);

  // 4. valid task -> APPROVE + proof that verifies locally
  const task1 = {
    type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_live_1', mode: 'competition',
    issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
      expiry_block: 8430000, current_block: 8420000,
      recipient: ADDR, condition_recipient: ADDR,
      amount: '500', max_transfer: '1000', proof_tx: '0xliveproof1',
    },
  };
  const t0 = Date.now();
  const r1 = await req('POST', '/gatekeeper', task1, true);
  const ms1 = Date.now() - t0;
  const j1 = JSON.parse(r1.body);
  check('valid task -> APPROVE/VALID_CONDITION', r1.status === 200 && j1.decision === 'APPROVE' && j1.reason_code === 'VALID_CONDITION', `${ms1}ms`);
  check('valid task response is HMAC-signed', verifyRespSig(r1));
  const v1 = j1.proof && j1.public_signals ? await snarkjs.groth16.verify(vk, j1.public_signals, j1.proof) : false;
  check('valid task proof verifies locally (registered VK)', v1 === true, `publicSignals=${j1.public_signals ? j1.public_signals.length : 0}`);
  check('response carries proof + 13 public_signals', !!j1.proof && Array.isArray(j1.public_signals) && j1.public_signals.length === 13);

  // 5. retry same task_id -> IDENTICAL response (same proof)
  const r1b = await req('POST', '/gatekeeper', task1, true);
  check('same task_id retry -> identical response body', r1b.body === r1.body);
  check('retry response is HMAC-signed', verifyRespSig(r1b));

  // 6. trap task -> REJECT + proof verifies
  const task2 = {
    type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_live_2', mode: 'competition',
    issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '999',
      expiry_block: 8430000, current_block: 8420000,
      recipient: ADDR, condition_recipient: ADDR,
      amount: '500', max_transfer: '1000', proof_tx: '0xliveproof2',
    },
  };
  const r2 = await req('POST', '/gatekeeper', task2, true);
  const j2 = JSON.parse(r2.body);
  check('trap task -> REJECT/THRESHOLD_MISMATCH', r2.status === 200 && j2.decision === 'REJECT' && j2.reason_code === 'THRESHOLD_MISMATCH');
  const v2 = j2.proof && j2.public_signals ? await snarkjs.groth16.verify(vk, j2.public_signals, j2.proof) : false;
  check('trap REJECT proof verifies locally', v2 === true);

  // 7. PROOF_REUSED: same proof_tx as task1, different task_id -> REJECT, NO proof
  const task3 = {
    type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_live_3', mode: 'competition',
    issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
      expiry_block: 8430000, current_block: 8420000,
      recipient: ADDR, condition_recipient: ADDR,
      amount: '500', max_transfer: '1000', proof_tx: '0xliveproof1',
    },
  };
  const r3 = await req('POST', '/gatekeeper', task3, true);
  const j3 = JSON.parse(r3.body);
  check('reused proof_tx -> REJECT/PROOF_REUSED, no proof', r3.status === 200 && j3.decision === 'REJECT' && j3.reason_code === 'PROOF_REUSED' && !j3.proof);

  // 8. unsigned task -> 401
  const r4 = await req('POST', '/gatekeeper', task1, false);
  check('unsigned task -> 401', r4.status === 401);

  // 9. VK_SUBSTITUTION trap
  const task5 = {
    type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_live_5', mode: 'competition',
    issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK, proof_vk: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      minimum: '1000', public_balance: '1460',
      expiry_block: 8430000, current_block: 8420000,
      recipient: ADDR, condition_recipient: ADDR,
      amount: '500', max_transfer: '1000', proof_tx: '0xliveproof5',
    },
  };
  const r5 = await req('POST', '/gatekeeper', task5, true);
  const j5 = JSON.parse(r5.body);
  check('VK_SUBSTITUTION trap -> REJECT + proof verifies', r5.status === 200 && j5.decision === 'REJECT' && j5.reason_code === 'VK_SUBSTITUTION' && j5.proof && (await snarkjs.groth16.verify(vk, j5.public_signals, j5.proof)));

  console.log(`\n${pass}/${total} live end-to-end checks passed`);
  server.kill();
  process.exit(pass === total ? 0 : 1);
}

main().catch((e) => { console.error('TEST ERROR:', e); process.exit(1); });
