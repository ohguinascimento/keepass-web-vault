import * as kdbxweb from 'kdbxweb';
import * as hashwasm from 'hash-wasm';

// Configure Argon2 implementation for kdbxweb using hash-wasm
export function initKdbxCrypto() {
  kdbxweb.CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type, version) => {
    // type: 0 = argon2d, 1 = argon2i, 2 = argon2id
    const fn = type === 0 ? hashwasm.argon2d : (type === 1 ? hashwasm.argon2i : hashwasm.argon2id);
    const hash = await fn({
      password: new Uint8Array(password),
      salt: new Uint8Array(salt),
      iterations: iterations,
      memorySize: memory,
      hashLength: length,
      parallelism: parallelism,
      outputType: 'binary'
    });
    return hash;
  });
}
