# Agent Games — Proof Gatekeeper

zkVerify Agent Games Season 01, Proof Gatekeeper track (100,000 VFY, top 3 split 50/30/20).

A Node.js agent that verifies zero-knowledge proofs (Groth16, BN254) for tournament tasks and returns a deterministic APPROVE/REJECT decision with the proof attached.

- `server.js` — HTTP server: `POST /gatekeeper` (HMAC-signed), `GET /health`.
- `gatekeeper/` — decision logic (`decide.js`, `prove.js`) + tests.
- `circuits/` — Groth16 circuit artifacts (`gatekeeper.wasm`, `gatekeeper_final.zkey`, `vk.json`).
- `shared/` — field arithmetic, HMAC, snark helpers.

## Run

```bash
npm install
npm start          # listens on $PORT (default 3000)
```

Set `AGENT_GAMES_HMAC_SECRET` (from the Agent Games Control Room) and `GATEKEEPER_TASK_ID_MODE=keccak` (default) in the environment.

## Verify locally

```bash
npm test           # 12 trap tests
node test-live.js  # end-to-end HTTP test
node verify-circuit.mjs
```
