#!/usr/bin/env node
// Independent verification of CloudPass's Argon2id usage.
//
// Why this exists
// ---------------
// RFC 9106's official test vectors also set a `secret` and `associated data`, which
// the RustCrypto `argon2` crate does not expose through its public API. So the Rust
// test suite cannot reproduce an external standard vector. What it does instead is
// freeze our own outputs (`argon2id_output_is_frozen`,
// `argon2id_recommended_output_is_frozen`).
//
// A frozen vector only catches *change*; it cannot catch the possibility that we were
// wrong from the beginning. This script closes that gap. It recomputes the same
// values with a completely independent implementation — Node's built-in Argon2, which
// is OpenSSL's — and fails if the two disagree. Agreement across two unrelated
// implementations on the same parameters is the evidence that our key derivation is
// correct, including that t/m/p are wired up the way we think.
//
// Usage
// -----
//   node scripts/verify-argon2-reference.mjs
//
// Requires Node.js with `crypto.argon2Sync` (Node 24 or newer).

import { argon2Sync } from 'node:crypto'

// Must match `SALT` in crates/cloudpass-core/src/kdf.rs tests: bytes 0x00..0x0f.
const SALT = Buffer.from(Array.from({ length: 16 }, (_, i) => i))
const PASSWORD = Buffer.from('correct horse battery staple', 'utf8')

// Must match the frozen assertions in crates/cloudpass-core/src/kdf.rs.
const CASES = [
  {
    name: 'OWASP_MINIMUM (m=19456 KiB, t=2, p=1)',
    memory: 19456,
    passes: 2,
    parallelism: 1,
    expected: '818259b6310026a8e0dbac5d2e6927abcfdb07b32258fac4f61b18b80f929085',
  },
  {
    name: 'RECOMMENDED (m=65536 KiB, t=3, p=4)',
    memory: 65536,
    passes: 3,
    parallelism: 4,
    expected: '853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e',
  },
]

if (typeof argon2Sync !== 'function') {
  console.error(
    'crypto.argon2Sync is unavailable. This check needs Node.js 24 or newer.\n' +
      `Running: ${process.version}`,
  )
  process.exit(2)
}

let failures = 0

for (const { name, memory, passes, parallelism, expected } of CASES) {
  const actual = argon2Sync('argon2id', {
    message: PASSWORD,
    nonce: SALT,
    parallelism,
    tagLength: 32,
    memory,
    passes,
  }).toString('hex')

  if (actual === expected) {
    console.log(`ok    ${name}`)
    console.log(`      ${actual}`)
  } else {
    failures += 1
    console.error(`FAIL  ${name}`)
    console.error(`      expected ${expected}`)
    console.error(`      actual   ${actual}`)
  }
}

if (failures > 0) {
  console.error(
    `\n${failures} of ${CASES.length} vectors disagreed with the OpenSSL reference.\n` +
      'Either the Rust parameters changed without updating this script, or the key\n' +
      'derivation in cloudpass-core is wrong. Both are release blockers.',
  )
  process.exit(1)
}

console.log(`\nAll ${CASES.length} vectors match the OpenSSL reference implementation.`)
