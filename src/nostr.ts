/**
 * NKIP-0001 Nostr witnessing — publish an attestation (kind 3711) so a party
 * OTHER than the user holds proof of the deposit/payout pair, and NIP-44 salt
 * recovery for non-XMR payouts.
 *
 * Depends on `nostr-tools` (an OPTIONAL peer dependency): import this module only
 * if you use Nostr witnessing. Receipt/commitment/salt_box in the other modules
 * have no Nostr dependency.
 */
import { finalizeEvent, SimplePool, nip19, nip44, type Event } from 'nostr-tools';
import type { Nkip01Attestation } from './receipt.js';

/** A reasonable default relay set (independent operators). Replace with your own
 *  — R2 only counts relays the issuer does NOT control. */
export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://relay.primal.net',
  'wss://nos.lol',
  'wss://relay.snort.social',
  'wss://nostr.mom',
];

export const EVENT_KIND_ATTESTATION = 3711;

function privBytes(privStr: string): Uint8Array {
  const s = String(privStr || '').trim();
  if (s.startsWith('nsec')) return nip19.decode(s).data as Uint8Array;
  return Uint8Array.from((s.match(/../g) || []).map((x) => parseInt(x, 16)));
}

/**
 * Sign the kind-3711 attestation event (synchronous — the id is computed
 * locally, so a create can attach it immediately and publish in the background).
 * `nostrPrivateKey` is the issuer's manifest Nostr key (nsec or 32-byte hex).
 */
export function buildAttestationEvent(nostrPrivateKey: string, att: Nkip01Attestation): Event | null {
  if (!nostrPrivateKey || !att.commitment || !att.sig) return null;
  try {
    return finalizeEvent({
      kind: EVENT_KIND_ATTESTATION,
      created_at: att.created_at,
      tags: [['c', att.commitment], ['i', att.issuer], ['v', att.v]],
      content: JSON.stringify(att),
    }, privBytes(nostrPrivateKey));
  } catch {
    return null;
  }
}

/**
 * Publish a signed attestation event and return how many relays accepted it.
 * Resolves as soon as `minOk` relays confirm (0 = wait for all), or at the 6s
 * budget. R2's counted-witness bar is 2 relays the issuer does not control.
 */
export async function publishAttestationEvent(event: Event, relays: string[] = DEFAULT_RELAYS, minOk = 0): Promise<number> {
  const pool = new SimplePool();
  try {
    return await new Promise<number>((resolve) => {
      let okN = 0, settled = 0, done = false;
      const n = relays.length;
      const finish = () => { if (!done) { done = true; clearTimeout(budget); resolve(okN); } };
      const budget = setTimeout(finish, 6000);
      for (const p of pool.publish(relays, event)) {
        Promise.resolve(p)
          .then(() => { okN++; if (minOk > 0 && okN >= minOk) finish(); })
          .catch(() => { /* this relay rejected */ })
          .finally(() => { settled++; if (settled >= n) finish(); });
      }
    });
  } catch {
    return 0;
  } finally {
    try { pool.close(relays); } catch { /* best-effort */ }
  }
}

/**
 * NKIP-0001 v2 salt recovery for a NON-XMR payout (R17): encrypt the salt (as
 * its 64-hex string) with NIP-44 v2 from the issuer's Nostr key to a
 * client-supplied `recoveryPubHex` (x-only secp256k1, 64 hex). Returns the
 * NIP-44 payload, or null when there is no key/salt or the pubkey is malformed
 * (then the salt lives only in the user's own receipt — a valid fallback).
 */
export function buildSaltNip44(nostrPrivateKey: string, recoveryPubHex: string, saltHex: string): string | null {
  try {
    if (!nostrPrivateKey || !saltHex) return null;
    const pub = String(recoveryPubHex || '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(pub)) return null;
    const ck = nip44.getConversationKey(privBytes(nostrPrivateKey), pub);
    return nip44.encrypt(saltHex, ck);
  } catch {
    return null;
  }
}
