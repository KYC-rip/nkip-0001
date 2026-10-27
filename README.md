# @kyc-rip/nkip-0001

Reference implementation of **[NKIP-0001 — Verifiable Deposit Receipts](https://nkips.org/nkip-0001/)**: signed, interoperable deposit receipts for non-custodial / no-KYC swaps, with salted commitments, Nostr attestation witnessing, and salt recovery for both XMR (`salt_box`) and non-XMR (`salt_nip44`) payouts.

Validated byte-for-byte against the spec's own v1 and v2 test vectors (run in CI).

Runs anywhere there's Web Crypto Ed25519: **Node ≥ 20, Cloudflare Workers, Deno, Bun, and modern browsers.**

```bash
npm install @kyc-rip/nkip-0001 @noble/curves @noble/hashes
# nostr-tools is an optional peer dep — add it only if you use Nostr witnessing / salt_nip44
npm install nostr-tools
```

## What it does (and doesn't)

This package is the **cryptographic core**: receipts, commitments, attestations, salt recovery, and the `.well-known/nkip01.json` manifest. It is transport- and storage-agnostic — the **Rule R2 withhold-until-witnessed flow** (where you store the held order, gate the deposit address on relay acceptance, and fail after the allowance) is application logic you build around these primitives.

## Quick start

```ts
import {
  signReceipt, verifyReceipt, nkip01Commitment, saltForDeposit, policyHash,
  signAttestation, buildSaltBox, buildAttestationEvent, publishAttestationEvent,
  type Nkip01Signer,
} from '@kyc-rip/nkip-0001';

const signer: Nkip01Signer = {
  privatePkcs8B64: process.env.RECEIPT_SIGNING_KEY!, // base64 PKCS#8 Ed25519
  publicRawB64: process.env.RECEIPT_PUBLIC_KEY!,     // base64 raw 32-byte pubkey
};

// 1. salt (v2): random for a transparent-chain deposit, zero for XMR
const salt = saltForDeposit('BTC');

// 2. a signed, interoperable receipt
const receipt = await signReceipt(signer, {
  issuer: 'example.swap',
  order_id: 'EX-1',
  deposit_asset: 'BTC', deposit_address: 'bc1q…', deposit_amount: '820000',
  payout_asset: 'XMR', payout_address: '4…', payout_amount: '1500000000000',
  rate_type: 'fixed',
  created_at: Math.floor(Date.now() / 1000),
  expires_at: Math.floor(Date.now() / 1000) + 3600,
  policy_hash: await policyHash(MY_POLICY_TEXT),
  salt,
});

// 3. the public commitment + an attestation to witness on Nostr
const commitment = await nkip01Commitment('example.swap', 'bc1q…', '4…', salt);
const saltBox = await buildSaltBox('4…', salt); // XMR payout → wallet recovers via view key
const att = await signAttestation(signer, { issuer: 'example.swap', commitment, created_at: receipt!.created_at, v: 'nkip01/2', ...(saltBox ? { salt_box: saltBox } : {}) });
const event = buildAttestationEvent(process.env.NOSTR_PRIVATE_KEY!, att!);
const ok = await publishAttestationEvent(event!, undefined, 2); // resolves at 2 relay OKs
```

Verifying (a directory, wallet or counterparty):

```ts
import { verifyReceipt, nkip01Commitment } from '@kyc-rip/nkip-0001';
const good = await verifyReceipt(receipt, issuerManifest.keys[0].public_key);
const bindsToMyAddrs = (await nkip01Commitment(receipt.issuer, receipt.deposit_address, receipt.payout_address, receipt.salt)) === att.commitment;
```

## API

| Module | Exports |
|--------|---------|
| receipt | `signReceipt`, `verifyReceipt`, `signAttestation`, `verifyAttestation`, `nkip01Commitment`, `jcsBytes`, `canonicalJson`, `nkip01KeyId`, `policyHash`, `saltForDeposit`, `randomSalt`, `ZERO_SALT`, `pubKeyB64Url`, types |
| saltBox | `decodeMoneroAddress`, `buildSaltBox`, `recoverSaltBox` |
| nostr | `buildAttestationEvent`, `publishAttestationEvent`, `buildSaltNip44`, `DEFAULT_RELAYS`, `EVENT_KIND_ATTESTATION` |
| manifest | `buildManifest` |

## Versions

- **v1**: unsalted commitment `SHA-256("nkip01/1" ‖ 0 ‖ issuer ‖ 0 ‖ deposit ‖ 0 ‖ payout)`.
- **v2** (spec rev 2026-10-27): adds a `salt` to the receipt and the commitment so the public attestation can't be linked to an order by someone who already knows the two addresses — random for transparent-chain deposits, zero for XMR. `salt_box` (Monero view-key ECDH) and `salt_nip44` (NIP-44 v2 to a client `recovery_pubkey`) let the counterparty recover the salt from the public attestation.

Both are supported; v1 receipts stay valid.

## License

MIT
