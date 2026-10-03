// Base32 RFC 4648 decode
function base32Decode(input) {
  const cleanInput = input.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const output = [];

  for (let i = 0; i < cleanInput.length; i++) {
    const idx = alphabet.indexOf(cleanInput[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

// Generate TOTP token
export async function generateTOTP(secretKey, period = 30, digits = 6, algorithm = 'SHA-1') {
  if (!secretKey) return null;

  // Clean secret if it's an otpauth:// URL
  let secret = secretKey.trim();
  if (secret.startsWith('otpauth://')) {
    try {
      const url = new URL(secret);
      secret = url.searchParams.get('secret') || secret;
      const p = url.searchParams.get('period');
      if (p) period = parseInt(p, 10);
      const d = url.searchParams.get('digits');
      if (d) digits = parseInt(d, 10);
      const a = url.searchParams.get('algorithm');
      if (a) algorithm = a.toUpperCase();
    } catch {
      // Fallback regex
      const match = secret.match(/[?&]secret=([A-Za-z2-7=]+)/i);
      if (match) secret = match[1];
    }
  }

  const keyBytes = base32Decode(secret);
  if (keyBytes.length === 0) return null;

  const epoch = Math.floor(Date.now() / 1000);
  const timeStep = Math.floor(epoch / period);
  const remainingSeconds = period - (epoch % period);

  const timeBuffer = new ArrayBuffer(8);
  const timeView = new DataView(timeBuffer);
  // Big-endian 64-bit integer
  timeView.setUint32(4, timeStep, false);

  const subtleAlgo = algorithm === 'SHA-256' ? 'SHA-256' : (algorithm === 'SHA-512' ? 'SHA-512' : 'SHA-1');

  try {
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: { name: subtleAlgo } },
      false,
      ['sign']
    );

    const signature = await window.crypto.subtle.sign('HMAC', cryptoKey, timeBuffer);
    const sigBytes = new Uint8Array(signature);

    const offset = sigBytes[sigBytes.length - 1] & 0x0f;
    const binary =
      ((sigBytes[offset] & 0x7f) << 24) |
      ((sigBytes[offset + 1] & 0xff) << 16) |
      ((sigBytes[offset + 2] & 0xff) << 8) |
      (sigBytes[offset + 3] & 0xff);

    const modulo = Math.pow(10, digits);
    const code = (binary % modulo).toString().padStart(digits, '0');

    return {
      code,
      remainingSeconds,
      period,
      formattedCode: code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code
    };
  } catch (err) {
    console.warn('TOTP calculation error:', err);
    return null;
  }
}
