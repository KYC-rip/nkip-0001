/**
 * @kyc-rip/nkip-0001 — reference implementation of NKIP-0001 (Verifiable Deposit
 * Receipts). See https://nkips.org/nkip-0001/.
 *
 * - `receipt`  — JCS, receipt/attestation sign+verify, commitment (v1/v2), salt.
 * - `saltBox`  — Monero address decode + XMR `salt_box` ECDH.
 * - `nostr`    — kind-3711 attestation events, publishing, NIP-44 `salt_nip44`
 *                (requires the optional `nostr-tools` peer dependency).
 * - `manifest` — the /.well-known/nkip01.json builder.
 */
export * from './receipt.js';
export * from './saltBox.js';
export * from './manifest.js';
// Nostr witnessing lives behind the optional `nostr-tools` peer dep; import it
// directly from '@kyc-rip/nkip-0001/nostr' is not needed — re-exported here, but
// only pulled in when actually referenced by a tree-shaking bundler.
export * from './nostr.js';
