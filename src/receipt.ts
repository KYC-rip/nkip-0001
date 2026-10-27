/**
 * NKIP-0001 receipts, commitments and attestations — the interoperable core.
 *
 * Canonical form is RFC 8785 (JCS): keys sorted (recursively), compact, the
 * `sig` field removed. Signatures are Ed25519 (WebCrypto), base64url no padding.
 * Amounts are decimal strings in the asset's base unit (piconero, satoshi, …).
 *
 * Validated byte-for-byte against the spec's own v1 and v2 test vectors.
 */

export const NKIP01_V1 = 'nkip01/1' as const;
export const NKIP01_V2 = 'nkip01/2' as const;
export type Nkip01Version = typeof NKIP01_V1 | typeof NKIP01_V2;
export type RateType = 'fixed' | 'float';

/** An Ed25519 signer: PKCS#8 private key and raw 32-byte public key, base64. */
export interface Nkip01Signer {
  /** base64 (standard or url) PKCS#8 Ed25519 private key. */
  privatePkcs8B64: string;
  /** base64 (standard or url) raw 32-byte Ed25519 public key. */
  publicRawB64: string;
}

export interface Nkip01Receipt {
  v: Nkip01Version;
  issuer: string;
  order_id: string;
  deposit_asset: string;
  deposit_address: string;
  deposit_amount: string;   // base-unit decimal string
  payout_asset: string;
  payout_address: string;
  payout_amount: string;    // base-unit decimal string (float = quoted floor)
  rate_type: RateType;
  created_at: number;       // unix seconds
  expires_at: number;       // unix seconds
  refund_address?: string;
  policy_hash: string;      // sha256 hex of the policy bytes in force
  salt?: string;            // v2 only: 32 bytes as 64 lowercase hex
  key_id: string;           // first 8 bytes of sha256(pubkey), hex
  sig?: string;             // Ed25519 over the JCS bytes, base64url no padding
}

export interface Nkip01SaltBox { r: string; ct: string }

export interface Nkip01Attestation {
  v: Nkip01Version;
  issuer: string;
  commitment: string;
  created_at: number;
  key_id: string;
  salt_box?: Nkip01SaltBox;   // v2 XMR-payout salt recovery (Monero ECDH)
  salt_nip44?: string;        // v2 non-XMR-payout salt recovery (NIP-44)
  sig?: string;
}

// ─── base64 / hex helpers (no external deps) ──────────────────────────────────

function b64ToBytes(b64: string): Uint8Array {
  const s = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
function toBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromBase64Url(s: string): Uint8Array {
  return b64ToBytes(s);
}
function hexToBytes(h: string): Uint8Array {
  return Uint8Array.from((h.match(/../g) || []).map((x) => parseInt(x, 16)));
}
function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource);
  return bytesToHex(new Uint8Array(d));
}

/** base64url of a standard-base64 raw public key (for the manifest). */
export function pubKeyB64Url(pubKeyB64: string): string {
  return pubKeyB64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ─── JCS (RFC 8785) ───────────────────────────────────────────────────────────

/** RFC 8785 (JCS) of any JSON value: object keys sorted RECURSIVELY, compact. */
export function canonicalJson(x: unknown): string {
  if (Array.isArray(x)) return '[' + x.map(canonicalJson).join(',') + ']';
  if (x && typeof x === 'object') {
    return '{' + Object.keys(x as Record<string, unknown>).sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalJson((x as Record<string, unknown>)[k])).join(',') + '}';
  }
  return JSON.stringify(x);
}

/** JCS bytes of a receipt with `sig` removed (what the signature covers). */
export function jcsBytes(receipt: Nkip01Receipt): string {
  const { sig: _omit, ...rest } = receipt;
  return canonicalJson(rest);
}

// ─── key_id / policy_hash ──────────────────────────────────────────────────────

/** key_id = first 8 bytes of SHA-256(raw public key), lowercase hex. */
export async function nkip01KeyId(pubKeyB64: string): Promise<string> {
  const raw = b64ToBytes(pubKeyB64);
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', raw as unknown as BufferSource));
  return bytesToHex(d.slice(0, 8));
}

/** policy_hash = SHA-256 hex of the EXACT policy bytes (UTF-8). */
export async function policyHash(policyText: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(policyText));
}

// ─── salt (v2) ─────────────────────────────────────────────────────────────────

export const ZERO_SALT = '0'.repeat(64);
const XMR_LIKE_DEPOSIT = new Set(['XMR']);

/** A random 32-byte salt as 64 lowercase hex. */
export function randomSalt(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * The salt for a receipt, chosen by the deposit asset: random for a transparent
 * chain (the on-chain deposit address is observable, so the public commitment
 * must be unlinkable), 32 zero bytes for XMR (the deposit subaddress is not
 * observable, so there is nothing to link).
 */
export function saltForDeposit(depositAsset: string): string {
  return XMR_LIKE_DEPOSIT.has(String(depositAsset || '').toUpperCase()) ? ZERO_SALT : randomSalt();
}

// ─── commitment ──────────────────────────────────────────────────────────────

/**
 * Commitment, lowercase hex — what a witness holds, never the plaintext
 * addresses. v1: SHA-256("nkip01/1" ‖ 0 ‖ issuer ‖ 0 ‖ dep ‖ 0 ‖ pay). v2: the
 * same under the "nkip01/2" tag with ‖ 0 ‖ <32 raw salt bytes> appended, which
 * makes the public commitment unlinkable to the order by anyone who merely knows
 * the two addresses. Pass `saltHex` (64 hex) for v2; omit it for v1.
 */
export async function nkip01Commitment(issuer: string, depositAddress: string, payoutAddress: string, saltHex?: string): Promise<string> {
  const enc = new TextEncoder();
  const z = new Uint8Array([0]);
  const v2 = saltHex != null;
  const parts: Uint8Array[] = [enc.encode(v2 ? NKIP01_V2 : NKIP01_V1), z, enc.encode(issuer), z, enc.encode(depositAddress), z, enc.encode(payoutAddress)];
  if (v2) parts.push(z, hexToBytes(saltHex));
  const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0; for (const p of parts) { buf.set(p, o); o += p.length; }
  return sha256Hex(buf);
}

// ─── sign / verify ──────────────────────────────────────────────────────────

async function importPkcs8(privatePkcs8B64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('pkcs8', b64ToBytes(privatePkcs8B64) as unknown as BufferSource, { name: 'Ed25519' }, false, ['sign']);
}

/**
 * Build and sign an NKIP-0001 receipt. A `salt` in `fields` makes it v2; without
 * one it is v1. Returns null if the signing key is unusable.
 */
export async function signReceipt(
  signer: Nkip01Signer,
  fields: Omit<Nkip01Receipt, 'v' | 'key_id' | 'sig'>,
): Promise<Nkip01Receipt | null> {
  try {
    const key_id = await nkip01KeyId(signer.publicRawB64);
    const v: Nkip01Version = fields.salt != null ? NKIP01_V2 : NKIP01_V1;
    const receipt: Nkip01Receipt = { v, ...fields, key_id };
    if (receipt.refund_address == null) delete receipt.refund_address;
    if (receipt.salt == null) delete receipt.salt;
    const sk = await importPkcs8(signer.privatePkcs8B64);
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, sk, new TextEncoder().encode(jcsBytes(receipt)) as unknown as BufferSource);
    receipt.sig = toBase64Url(sig);
    return receipt;
  } catch {
    return null;
  }
}

/** Verify a receipt against a raw Ed25519 public key (base64 or base64url). */
export async function verifyReceipt(receipt: Nkip01Receipt, pubKeyB64: string): Promise<boolean> {
  try {
    if (!receipt.sig) return false;
    const key = await crypto.subtle.importKey('raw', b64ToBytes(pubKeyB64) as unknown as BufferSource, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify(
      { name: 'Ed25519' }, key,
      fromBase64Url(receipt.sig) as unknown as BufferSource,
      new TextEncoder().encode(jcsBytes(receipt)) as unknown as BufferSource,
    );
  } catch {
    return false;
  }
}

/**
 * Sign an attestation — the small object a witness stores. Ed25519 over the JCS
 * of the non-sig fields, with the SAME key as the receipt. v2 may carry a
 * `salt_box` (XMR payout) or `salt_nip44` (other) for salt recovery.
 */
export async function signAttestation(
  signer: Nkip01Signer,
  fields: { issuer: string; commitment: string; created_at: number; v?: Nkip01Version; salt_box?: Nkip01SaltBox; salt_nip44?: string },
): Promise<Nkip01Attestation | null> {
  try {
    const key_id = await nkip01KeyId(signer.publicRawB64);
    const att: Nkip01Attestation = { v: fields.v ?? NKIP01_V1, issuer: fields.issuer, commitment: fields.commitment, created_at: fields.created_at, key_id };
    if (fields.salt_box) att.salt_box = fields.salt_box;
    if (fields.salt_nip44) att.salt_nip44 = fields.salt_nip44;
    const { sig: _omit, ...rest } = att;
    const sk = await importPkcs8(signer.privatePkcs8B64);
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, sk, new TextEncoder().encode(canonicalJson(rest)) as unknown as BufferSource);
    att.sig = toBase64Url(sig);
    return att;
  } catch {
    return null;
  }
}

/** Verify an attestation against a raw Ed25519 public key. */
export async function verifyAttestation(att: Nkip01Attestation, pubKeyB64: string): Promise<boolean> {
  try {
    if (!att.sig) return false;
    const { sig, ...rest } = att;
    const key = await crypto.subtle.importKey('raw', b64ToBytes(pubKeyB64) as unknown as BufferSource, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify(
      { name: 'Ed25519' }, key,
      fromBase64Url(sig!) as unknown as BufferSource,
      new TextEncoder().encode(canonicalJson(rest)) as unknown as BufferSource,
    );
  } catch {
    return false;
  }
}
