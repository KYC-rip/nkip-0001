/** NKIP-0001 conformance — the library validated against the spec's OWN
 *  published test vectors (v1 + v2), byte-for-byte. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { nip44, getPublicKey, generateSecretKey } from 'nostr-tools';
import {
  jcsBytes, nkip01KeyId, policyHash, verifyReceipt, nkip01Commitment,
  type Nkip01Receipt,
} from '../src/receipt.js';
import { buildSaltBox, recoverSaltBox, decodeMoneroAddress } from '../src/saltBox.js';
import { buildSaltNip44 } from '../src/nostr.js';

const load = (f: string) => JSON.parse(readFileSync(fileURLToPath(new URL(`./fixtures/${f}`, import.meta.url)), 'utf8'));
const V1 = load('nkip01-vectors-v1.json');
const V2 = load('nkip01-vectors-v2.json');
const v1valid = V1.vectors.find((v: any) => v.name === 'valid');
const v1tampered = V1.vectors.find((v: any) => v.name === 'tampered-payout');

describe('NKIP-0001 v1 (official vectors)', () => {
  it('produces the spec JCS canonical form byte-for-byte', () => {
    expect(jcsBytes(v1valid.receipt as Nkip01Receipt)).toBe(v1valid.jcs_without_sig);
  });
  it('derives key_id, policy_hash', async () => {
    expect(await nkip01KeyId(V1.public_key_b64u)).toBe(V1.key_id);
    expect(await policyHash(V1.policy_text)).toBe(V1.manifest.policies[0].policy_hash);
  });
  it('verifies valid + rejects tampered', async () => {
    expect(await verifyReceipt(v1valid.receipt as Nkip01Receipt, V1.public_key_b64u)).toBe(true);
    expect(await verifyReceipt(v1tampered.receipt as Nkip01Receipt, V1.public_key_b64u)).toBe(false);
  });
  it('computes the v1 commitment', async () => {
    const r = v1valid.receipt;
    expect(await nkip01Commitment(r.issuer, r.deposit_address, r.payout_address)).toBe(v1valid.commitment);
  });
});

describe('NKIP-0001 v2 salted commitment + salt recovery (official vectors)', () => {
  it('computes the salted v2 commitment + verifies every v2 receipt', async () => {
    for (const c of V2.cases) {
      expect(await nkip01Commitment(c.receipt.issuer, c.receipt.deposit_address, c.receipt.payout_address, c.receipt.salt)).toBe(c.commitment);
      expect(await verifyReceipt(c.receipt as Nkip01Receipt, V2.public_key_b64u)).toBe(true);
    }
  });

  it('decodes Monero payout addresses (primary + subaddress)', () => {
    expect(decodeMoneroAddress(V2.cases[0].receipt.payout_address)?.net).toBe(18);
    expect(decodeMoneroAddress(V2.cases[1].receipt.payout_address)?.net).toBe(42);
  });

  it('wallet recovers the salt from the vector salt_box', async () => {
    for (const c of V2.cases) {
      if (!c.attestation?.salt_box) continue;
      expect(await recoverSaltBox(c.attestation.salt_box, V2.test_wallet_private_view_key)).toBe(c.receipt.salt);
    }
  });

  it('round-trips a freshly built salt_box (issuer → wallet)', async () => {
    for (const c of V2.cases) {
      if (!c.attestation?.salt_box) continue;
      const box = await buildSaltBox(c.receipt.payout_address, c.receipt.salt);
      expect(box).not.toBeNull();
      expect(await recoverSaltBox(box!, V2.test_wallet_private_view_key)).toBe(c.receipt.salt);
    }
  });

  it('salt_box is null for non-XMR / zero salt', async () => {
    expect(await buildSaltBox('bc1qexampledepositv27', V2.cases[0].receipt.salt)).toBeNull();
    expect(await buildSaltBox(V2.cases[0].receipt.payout_address, '0'.repeat(64))).toBeNull();
  });

  it('salt_nip44 round-trips to the recovery wallet (NIP-44 v2)', () => {
    const issuerPriv = generateSecretKey();
    const issuerPub = getPublicKey(issuerPriv);
    const recPriv = generateSecretKey();
    const recPub = getPublicKey(recPriv);
    const salt = V2.cases[0].receipt.salt;
    const ct = buildSaltNip44(Buffer.from(issuerPriv).toString('hex'), recPub, salt);
    expect(ct).toBeTruthy();
    expect(nip44.decrypt(ct!, nip44.getConversationKey(recPriv, issuerPub))).toBe(salt);
    // guards
    expect(buildSaltNip44(Buffer.from(issuerPriv).toString('hex'), 'bad', salt)).toBeNull();
    expect(buildSaltNip44('', recPub, salt)).toBeNull();
  });
});
