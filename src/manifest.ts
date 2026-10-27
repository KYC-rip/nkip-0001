/**
 * NKIP-0001 issuer manifest (served at https://<issuer>/.well-known/nkip01.json).
 * All values are public: the Ed25519 receipt public key + its key_id, the Nostr
 * x-only pubkey, the relay set, the policy URL(s) + hash, and a dispute channel.
 */
import { nkip01KeyId, pubKeyB64Url } from './receipt.js';

export interface Nkip01ManifestKey {
  key_id: string;
  alg: 'ed25519';
  public_key: string;    // base64url, 32 bytes
  not_before: number;
  revoked_at: number | null;
  rotated_from: string | null;
  rotation_sig: string | null;
}

export interface Nkip01Manifest {
  v: 'nkip01/1';
  issuer: string;
  adopted_at: number;
  keys: Nkip01ManifestKey[];
  nostr_pubkey: string;
  relays: string[];
  policies: { policy_hash: string; url: string }[];
  disputes?: Record<string, string>;
}

export interface BuildManifestInput {
  issuer: string;
  /** base64 (standard or url) raw 32-byte Ed25519 receipt public key. */
  receiptPublicKeyB64: string;
  /** issuer's Nostr x-only public key, 32-byte hex. */
  nostrPubkeyHex: string;
  relays: string[];
  policies: { policy_hash: string; url: string }[];
  /** unix seconds the "no receipt" rule begins. */
  adoptedAt: number;
  disputes?: Record<string, string>;
}

/** Build a schema-valid NKIP-0001 manifest from public inputs. */
export async function buildManifest(input: BuildManifestInput): Promise<Nkip01Manifest> {
  const key_id = await nkip01KeyId(input.receiptPublicKeyB64);
  return {
    v: 'nkip01/1',
    issuer: input.issuer,
    adopted_at: input.adoptedAt,
    keys: [{
      key_id,
      alg: 'ed25519',
      public_key: pubKeyB64Url(input.receiptPublicKeyB64),
      not_before: input.adoptedAt,
      revoked_at: null,
      rotated_from: null,
      rotation_sig: null,
    }],
    nostr_pubkey: input.nostrPubkeyHex,
    relays: input.relays,
    policies: input.policies,
    ...(input.disputes ? { disputes: input.disputes } : {}),
  };
}
