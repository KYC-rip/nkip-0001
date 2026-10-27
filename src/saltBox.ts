/**
 * NKIP-0001 v2 `salt_box` — hand a receipt's random salt to an XMR *payout*
 * wallet through the public attestation, recoverable with only its private view
 * key (R17). Monero one-time-key ECDH:
 *
 *   primary / integrated address:  R = r·G ,          derivation = 8·r·V(view)
 *   subaddress:                     R = r·D(spend) ,    derivation = 8·r·C(view)
 *   the wallet recovers the SAME derivation as 8·v·R with its private view key v.
 *
 *   salt_box = { r, ct }   ct = salt XOR SHA-256("nkip01/2 salt" ‖ 0x00 ‖ derivation)
 *
 * Validated byte-for-byte (primary + subaddress) against the official v2 vectors
 * and by issuer→wallet round-trip against the vector's view key.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import type { Nkip01SaltBox } from './receipt.js';

const Point = ed25519.Point;
const L = 2n ** 252n + 27742317777372353535851937790883648493n; // ed25519 group order

// Monero base58: 8-byte blocks of 11 chars (a short final block is fewer).
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BLOCK_CHARS = [0, 2, 3, 5, 6, 7, 9, 10, 11];

function decodeBlock(chars: string, out: number[]): boolean {
  const size = BLOCK_CHARS.indexOf(chars.length);
  if (size < 1) return false;
  let n = 0n;
  for (const ch of chars) {
    const d = B58.indexOf(ch);
    if (d < 0) return false;
    n = n * 58n + BigInt(d);
  }
  if (n >> BigInt(size * 8)) return false;
  for (let i = size - 1; i >= 0; i--) out.push(Number((n >> BigInt(i * 8)) & 0xffn));
  return true;
}

export interface MoneroAddressKeys { net: number; spend: Uint8Array; view: Uint8Array }

/** Decode a Monero address to its network byte + public spend/view keys, or null
 *  if it is not a standard (18), subaddress (42) or integrated (19) mainnet
 *  address. */
export function decodeMoneroAddress(addr: string): MoneroAddressKeys | null {
  const a = String(addr || '');
  if (a.length !== 95 && a.length !== 106) return null;
  const bytes: number[] = [];
  for (let i = 0; i < a.length; i += 11) {
    if (!decodeBlock(a.slice(i, Math.min(i + 11, a.length)), bytes)) return null;
  }
  const net = bytes[0];
  if (net !== 18 && net !== 42 && net !== 19) return null;
  if (bytes.length < 65) return null;
  return { net, spend: Uint8Array.from(bytes.slice(1, 33)), view: Uint8Array.from(bytes.slice(33, 65)) };
}

const ZERO_SALT = '0'.repeat(64);
const hexToBytes = (h: string) => Uint8Array.from((h.match(/../g) || []).map((x) => parseInt(x, 16)));
const bytesToHex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
const leToBig = (b: Uint8Array) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };

async function sha256(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', b as unknown as BufferSource));
}

/**
 * Build the `salt_box` for an XMR payout address, or null when the address is
 * not XMR or the salt is all-zero (nothing to protect). `saltHex` is the 64-hex
 * salt already in the receipt.
 */
export async function buildSaltBox(payoutAddress: string, saltHex: string): Promise<Nkip01SaltBox | null> {
  try {
    if (!saltHex || saltHex === ZERO_SALT) return null;
    const keys = decodeMoneroAddress(payoutAddress);
    if (!keys) return null;
    let r = leToBig(crypto.getRandomValues(new Uint8Array(32))) % L;
    if (r === 0n) r = 1n;
    const viewPoint = Point.fromBytes(keys.view);
    const R = keys.net === 42 ? Point.fromBytes(keys.spend).multiply(r) : Point.BASE.multiply(r);
    const derivation = viewPoint.multiply(r).multiply(8n).toBytes();
    const k = await sha256(new Uint8Array([...new TextEncoder().encode('nkip01/2 salt'), 0, ...derivation]));
    const salt = hexToBytes(saltHex);
    const ct = new Uint8Array(32);
    for (let i = 0; i < 32; i++) ct[i] = salt[i] ^ k[i];
    return { r: bytesToHex(R.toBytes()), ct: bytesToHex(ct) };
  } catch {
    return null;
  }
}

/**
 * The wallet side: recover a salt_box's salt with the private view key (for
 * tests / verifiers). `viewKeyHex` is the 32-byte private view key, hex.
 */
export async function recoverSaltBox(box: Nkip01SaltBox, viewKeyHex: string): Promise<string> {
  const v = leToBig(hexToBytes(viewKeyHex)) % L;
  const derivation = Point.fromHex(box.r).multiply(v).multiply(8n).toBytes();
  const k = await sha256(new Uint8Array([...new TextEncoder().encode('nkip01/2 salt'), 0, ...derivation]));
  const ct = hexToBytes(box.ct);
  const salt = new Uint8Array(32);
  for (let i = 0; i < 32; i++) salt[i] = ct[i] ^ k[i];
  return bytesToHex(salt);
}
