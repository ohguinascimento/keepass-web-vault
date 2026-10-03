// Cryptographically secure password generator
export function generatePassword(options = {}) {
  const {
    length = 20,
    uppercase = true,
    lowercase = true,
    numbers = true,
    symbols = true,
    avoidAmbiguous = true
  } = options;

  let upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let lowerChars = 'abcdefghijklmnopqrstuvwxyz';
  let numberChars = '0123456789';
  let symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';

  if (avoidAmbiguous) {
    upperChars = upperChars.replace(/[IO]/g, '');
    lowerChars = lowerChars.replace(/[lo]/g, '');
    numberChars = numberChars.replace(/[01]/g, '');
    symbolChars = symbolChars.replace(/[|]/g, '');
  }

  let charset = '';
  const requiredChars = [];

  const getRandomChar = (str) => {
    const arr = new Uint32Array(1);
    window.crypto.getRandomValues(arr);
    return str[arr[0] % str.length];
  };

  if (uppercase && upperChars.length) {
    charset += upperChars;
    requiredChars.push(getRandomChar(upperChars));
  }
  if (lowercase && lowerChars.length) {
    charset += lowerChars;
    requiredChars.push(getRandomChar(lowerChars));
  }
  if (numbers && numberChars.length) {
    charset += numberChars;
    requiredChars.push(getRandomChar(numberChars));
  }
  if (symbols && symbolChars.length) {
    charset += symbolChars;
    requiredChars.push(getRandomChar(symbolChars));
  }

  if (charset.length === 0) {
    charset = lowerChars + numberChars;
  }

  const result = [...requiredChars];
  const remaining = Math.max(0, length - result.length);
  const randomValues = new Uint32Array(remaining);
  window.crypto.getRandomValues(randomValues);

  for (let i = 0; i < remaining; i++) {
    result.push(charset[randomValues[i] % charset.length]);
  }

  // Cryptographically shuffle result array using Fisher-Yates
  for (let i = result.length - 1; i > 0; i--) {
    const rand = new Uint32Array(1);
    window.crypto.getRandomValues(rand);
    const j = rand[0] % (i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }

  return result.join('');
}
