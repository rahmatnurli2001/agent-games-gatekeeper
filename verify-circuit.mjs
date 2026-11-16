import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { proveTask } = require('./gatekeeper/prove.js');
const { verifyLocally } = require('./shared/snark.js');
const { decide } = require('./gatekeeper/decide.js');

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR = '0x1111111111111111111111111111111111111111';
const OTHER = '0x2222222222222222222222222222222222222222';

const valid = {
  task_id: 'gk_24_9d1', registered_vk: VK, proof_vk: VK,
  minimum: '1000', public_balance: '1460', expiry_block: '8430000', current_block: '8420000',
  recipient: ADDR, condition_recipient: ADDR,
  amount: '500', max_transfer: '1000', proof_tx: '0xabc123',
};

// 1. Valid APPROVE — show public signals
console.log('=== 1. Valid APPROVE ===');
const d1 = decide(valid);
console.log('decision:', d1.decision, '/', d1.reason_code);
const t0 = Date.now();
const { proof, publicSignals } = await proveTask(valid, d1.decision, 'keccak');
console.log('prove time:', Date.now() - t0, 'ms');
console.log('publicSignals count:', publicSignals.length);
console.log('publicSignals:', JSON.stringify(publicSignals, null, 1));
const ok = await verifyLocally('gatekeeper', publicSignals, proof);
console.log('verify:', ok ? 'OK' : 'FAIL');
console.log('proof bytes:', JSON.stringify(proof).length);
console.log('proof.pi_a:', proof.pi_a);
console.log('proof.protocol:', proof.protocol, '| curve:', proof.curve);

// 2. Wrong decision: APPROVE a trap (recipient mismatch) — should FAIL
console.log('\n=== 2. Wrong APPROVE on RECIPIENT_MISMATCH trap (expect fullProve FAIL) ===');
const trap = { ...valid, recipient: OTHER, proof_tx: '0xdef456' };
const d2 = decide(trap);
console.log('correct decision:', d2.decision, '/', d2.reason_code);
try {
  await proveTask(trap, 'APPROVE', 'keccak');
  console.log('UNEXPECTED: fullProve SUCCEEDED for wrong APPROVE — circuit does NOT enforce decision!');
} catch (e) {
  console.log('fullProve FAILED as expected:', String(e.message).slice(0, 160));
}

// 3. Wrong decision: REJECT a valid condition — should FAIL
console.log('\n=== 3. Wrong REJECT on valid condition (expect fullProve FAIL) ===');
try {
  await proveTask(valid, 'REJECT', 'keccak');
  console.log('UNEXPECTED: fullProve SUCCEEDED for wrong REJECT — circuit does NOT enforce decision!');
} catch (e) {
  console.log('fullProve FAILED as expected:', String(e.message).slice(0, 160));
}

// 4. Correct REJECT on a trap — should succeed
console.log('\n=== 4. Correct REJECT on trap (expect verify OK) ===');
const { proof: p4, publicSignals: s4 } = await proveTask(trap, 'REJECT', 'keccak');
const ok4 = await verifyLocally('gatekeeper', s4, p4);
console.log('REJECT trap proof verify:', ok4 ? 'OK' : 'FAIL');
console.log('REJECT publicSignals[11] (decision):', s4[11], '(expect 0)');
console.log('APPROVE publicSignals[11] (decision):', publicSignals[11], '(expect 1)');
console.log('\n=== ALL CIRCUIT CHECKS DONE ===');
