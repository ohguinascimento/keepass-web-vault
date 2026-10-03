// Calculate password strength, entropy and score (1 to 4)
export function evaluatePassword(pwd) {
  if (!pwd) {
    return {
      score: 0,
      label: 'Vazio',
      color: '#6b7280',
      entropy: 0,
      length: 0,
      hasUpper: false,
      hasLower: false,
      hasNumber: false,
      hasSymbol: false
    };
  }

  const length = pwd.length;
  const hasLower = /[a-z]/.test(pwd);
  const hasUpper = /[A-Z]/.test(pwd);
  const hasNumber = /[0-9]/.test(pwd);
  const hasSymbol = /[^a-zA-Z0-9]/.test(pwd);

  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasNumber) poolSize += 10;
  if (hasSymbol) poolSize += 33;

  const entropy = Math.round(length * (Math.log2(poolSize || 1)));

  let score = 1;
  let label = 'Muito Fraca';
  let color = '#f43f5e';

  if (length >= 16 && (hasLower && hasUpper && hasNumber && hasSymbol)) {
    score = 4;
    label = 'Excelente';
    color = '#10b981';
  } else if (length >= 12 && ((hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasNumber ? 1 : 0) + (hasSymbol ? 1 : 0) >= 3)) {
    score = 3;
    label = 'Forte';
    color = '#06b6d4';
  } else if (length >= 8 && ((hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasNumber ? 1 : 0) + (hasSymbol ? 1 : 0) >= 2)) {
    score = 2;
    label = 'Média';
    color = '#f59e0b';
  }

  return {
    score,
    label,
    color,
    entropy,
    length,
    hasUpper,
    hasLower,
    hasNumber,
    hasSymbol
  };
}
