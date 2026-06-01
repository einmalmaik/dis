import { defineConfig } from 'tsup';

/**
 * Each public module is a separate entry point so that consumers can import
 * narrow surfaces (e.g. `@dis/shield/aead`) and bundlers can tree-shake
 * unused modules. The barrel entry (`index`) re-exports the stable public SDK.
 */
export default defineConfig({
    entry: {
        index: 'src/index.ts',
        'core/index': 'src/core/index.ts',
        'random/index': 'src/random/index.ts',
        'secure-memory/index': 'src/secure-memory/index.ts',
        'kdf/index': 'src/kdf/index.ts',
        'aead/index': 'src/aead/index.ts',
        'format-versioning/index': 'src/format-versioning/index.ts',
        'vault-encryption/index': 'src/vault-encryption/index.ts',
        'file-encryption/index': 'src/file-encryption/index.ts',
        'key-management/index': 'src/key-management/index.ts',
        'asymmetric/index': 'src/asymmetric/index.ts',
        'post-quantum/index': 'src/post-quantum/index.ts',
        'vault-crypto/index': 'src/vault-crypto/index.ts',
        'integrity/index': 'src/integrity/index.ts',
        'migrations/index': 'src/migrations/index.ts',
    },
    format: ['esm'],
    dts: true,
    clean: true,
    sourcemap: true,
    treeshake: true,
    target: 'es2022',
    // Keep crypto libraries external so consumers control the exact version
    // and so the post-quantum dependency stays optional.
    external: ['hash-wasm', '@noble/post-quantum'],
});
