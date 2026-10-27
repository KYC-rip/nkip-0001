import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  treeshake: true,
  // Peer deps are provided by the consumer — never bundle them.
  external: ['@noble/curves', '@noble/hashes', 'nostr-tools'],
});
