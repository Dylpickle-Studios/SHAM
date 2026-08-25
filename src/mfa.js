const crypto = require('node:crypto');
const { encrypt, decrypt } = require('./secret-store');

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(input) {
  const normalized = String(input || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const character of normalized) {
    const index = BASE32.indexOf(character);
    if (index < 0) continue;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function hotp(secret, counter, digits = 6) {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', base32Decode(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const value = (digest.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits);
  return String(value).padStart(digits, '0');
}

function totp(secret, timestamp = Date.now(), stepSeconds = 30) {
  return hotp(secret, Math.floor(timestamp / 1000 / stepSeconds));
}

function verifyTotp(secret, code, { timestamp = Date.now(), window = 1 } = {}) {
  const supplied = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(supplied)) return false;
  for (let offset = -window; offset <= window; offset += 1) {
    const expected = totp(secret, timestamp + offset * 30_000);
    if (crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) return true;
  }
  return false;
}

function generateTotpSetup(username, issuer = 'SHAM') {
  const secret = base32Encode(crypto.randomBytes(20));
  const label = encodeURIComponent(`${issuer}:${username}`);
  const url = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  return { secret, url };
}

function generateRecoveryCodes(count = 10) {
  return Array.from({ length: count }, () => (crypto.randomBytes(5).toString('hex').toUpperCase().match(/.{1,5}/g) || []).join('-'));
}

function hashRecoveryCode(code) {
  return crypto.createHash('sha256').update(String(code).replace(/[^a-z0-9]/gi, '').toUpperCase()).digest('hex');
}

function consumeRecoveryCode(db, userId, supplied) {
  const user = db.prepare('SELECT recovery_codes_json FROM users WHERE id = ?').get(userId);
  let hashes;
  try { hashes = JSON.parse(user?.recovery_codes_json || '[]'); } catch { hashes = []; }
  const hash = hashRecoveryCode(supplied);
  const index = hashes.findIndex((value) => value === hash);
  if (index < 0) return false;
  hashes.splice(index, 1);
  db.prepare('UPDATE users SET recovery_codes_json = ? WHERE id = ?').run(JSON.stringify(hashes), userId);
  return true;
}

function enableTotp(db, userId, secret, recoveryCodes) {
  db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1, recovery_codes_json = ? WHERE id = ?')
    .run(encrypt(secret), JSON.stringify(recoveryCodes.map(hashRecoveryCode)), userId);
}

function disableTotp(db, userId) {
  db.prepare("UPDATE users SET totp_secret = '', totp_enabled = 0, recovery_codes_json = '[]' WHERE id = ?").run(userId);
}

function userTotpSecret(user) {
  return user?.totp_secret ? decrypt(user.totp_secret) : '';
}

module.exports = {
  base32Encode,
  base32Decode,
  hotp,
  totp,
  verifyTotp,
  generateTotpSetup,
  generateRecoveryCodes,
  hashRecoveryCode,
  consumeRecoveryCode,
  enableTotp,
  disableTotp,
  userTotpSecret
};
