const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DATA_DIR } = require('./config');

const KEYRING_PATH = path.join(DATA_DIR, '.master-keyring.json');
const ENCRYPTED_PREFIX = 'enc:v1:';

/** @typedef {{ active: Buffer, previous: Buffer[], external: boolean }} Keyring */

/** @type {Keyring | null} */
let keyring = null;

function decodeConfiguredKey(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  let key;
  if (/^[0-9a-f]{64}$/i.test(raw)) key = Buffer.from(raw, 'hex');
  else {
    try { key = Buffer.from(raw, 'base64url'); }
    catch { throw new Error('SHAM_MASTER_KEY must be 32 bytes encoded as hex or base64url.'); }
  }
  if (key.length !== 32) throw new Error('SHAM_MASTER_KEY must decode to exactly 32 bytes.');
  return key;
}

function serializeKey(key) {
  return Buffer.from(key).toString('base64url');
}

function writeKeyring(value) {
  const temporary = `${KEYRING_PATH}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, KEYRING_PATH);
  try { fs.chmodSync(KEYRING_PATH, 0o600); } catch { /* Read-only or non-POSIX storage. */ }
}

/** @returns {Keyring} */
function loadKeyring() {
  if (keyring) return keyring;
  const configured = decodeConfiguredKey(process.env.SHAM_MASTER_KEY);
  if (configured) {
    keyring = { active: configured, previous: [], external: true };
    return keyring;
  }

  if (fs.existsSync(KEYRING_PATH)) {
    const parsed = JSON.parse(fs.readFileSync(KEYRING_PATH, 'utf8'));
    const active = decodeConfiguredKey(parsed.active);
    const previous = (Array.isArray(parsed.previous) ? parsed.previous : []).map(decodeConfiguredKey).filter(Boolean).slice(0, 2);
    keyring = { active, previous, external: false };
    try { fs.chmodSync(KEYRING_PATH, 0o600); } catch { /* Best effort. */ }
    return keyring;
  }

  const active = crypto.randomBytes(32);
  writeKeyring({ active: serializeKey(active), previous: [] });
  keyring = { active, previous: [], external: false };
  return keyring;
}

function isEncrypted(value) {
  return typeof value === 'string' && value.startsWith(ENCRYPTED_PREFIX);
}

function encrypt(value, key = loadKeyring().active) {
  if (value === null || value === undefined || value === '') return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${ENCRYPTED_PREFIX}${iv.toString('base64url')}:${tag.toString('base64url')}:${ciphertext.toString('base64url')}`;
}

function decryptWithKey(value, key) {
  const parts = String(value).slice(ENCRYPTED_PREFIX.length).split(':');
  if (parts.length !== 3) throw new Error('Encrypted secret has an invalid format.');
  const [ivRaw, tagRaw, dataRaw] = parts;
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivRaw, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagRaw, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(dataRaw, 'base64url')), decipher.final()]).toString('utf8');
}

function decrypt(value, fallback = '') {
  if (value === null || value === undefined || value === '') return fallback;
  if (!isEncrypted(value)) return String(value);
  const ring = loadKeyring();
  for (const key of [ring.active, ...ring.previous]) {
    try { return decryptWithKey(value, key); } catch { /* Try the previous key during rotation recovery. */ }
  }
  throw new Error('A saved secret could not be decrypted with the configured master key.');
}

function encryptedJson(value) {
  return encrypt(JSON.stringify(value));
}

function decryptedJson(value, fallback = null) {
  try { return JSON.parse(decrypt(value)); } catch { return fallback; }
}

/**
 * @param {import('better-sqlite3').Database} db
 * @param {string} key
 * @param {string} [fallback]
 * @returns {string}
 */
function getSecretSetting(db, key, fallback = '') {
  const row = /** @type {SettingRow | undefined} */ (db.prepare('SELECT value FROM settings WHERE key = ?').get(key));
  return row ? decrypt(row.value, fallback) : fallback;
}

/** @typedef {{ value: string }} SettingRow */

/**
 * @param {import('better-sqlite3').Database} db
 * @param {string} key
 * @param {unknown} value
 */
function setSecretSetting(db, key, value) {
  const encrypted = value ? encrypt(String(value)) : '';
  db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
  `).run(key, encrypted);
}

function migrateKnownSecrets(db) {
  const settingKeys = ['cloudflare_api_token', 'cloudflare_tunnel_token', 'cloudflare_tunnel_api_token', 'pangolin_newt_secret', 'backup_config', 'alert_delivery_config', 'prometheus_token', 'otel_headers', 'oidc_client_secret'];
  const updateSetting = db.prepare('UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?');
  const updatePlugin = db.prepare('UPDATE plugin_settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE plugin_id = ? AND key = ?');
  const updateDatabaseProfile = db.prepare('UPDATE database_profiles SET connection_value = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
  const updateEnvironment = db.prepare('UPDATE site_env SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE site_id = ? AND key = ?');
  const updateAlertDestination = db.prepare('UPDATE alert_destinations SET config_encrypted = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
  const transaction = db.transaction(() => {
    for (const key of settingKeys) {
      const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
      if (row?.value && !isEncrypted(row.value)) updateSetting.run(encrypt(row.value), key);
    }
    const plugins = db.prepare('SELECT id, manifest_json FROM plugins').all();
    for (const plugin of plugins) {
      let manifest;
      try { manifest = JSON.parse(plugin.manifest_json); } catch { continue; }
      const secretKeys = new Set((manifest.settings || []).filter((setting) => setting.type === 'password').map((setting) => setting.key));
      for (const row of db.prepare('SELECT key, value FROM plugin_settings WHERE plugin_id = ?').all(plugin.id)) {
        if (!secretKeys.has(row.key)) continue;
        let stored;
        try { stored = JSON.parse(row.value); } catch { stored = row.value; }
        if (!stored || isEncrypted(stored)) continue;
        updatePlugin.run(JSON.stringify(encrypt(String(stored))), plugin.id, row.key);
      }
    }
    for (const row of db.prepare("SELECT site_id, token FROM site_cloudflare_tunnels WHERE token != ''").all()) {
      if (!isEncrypted(row.token)) db.prepare('UPDATE site_cloudflare_tunnels SET token = ?, updated_at = CURRENT_TIMESTAMP WHERE site_id = ?').run(encrypt(row.token), row.site_id);
    }
    for (const user of db.prepare('SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL AND totp_secret != ?').all('')) {
      if (!isEncrypted(user.totp_secret)) db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(encrypt(user.totp_secret), user.id);
    }
    for (const row of db.prepare("SELECT id, connection_value FROM database_profiles WHERE connection_value != ''").all()) {
      if (!isEncrypted(row.connection_value)) updateDatabaseProfile.run(encrypt(row.connection_value), row.id);
    }
    for (const row of db.prepare("SELECT site_id, key, value FROM site_env WHERE secret = 1 AND value != ''").all()) {
      if (!isEncrypted(row.value)) updateEnvironment.run(encrypt(row.value), row.site_id, row.key);
    }
    for (const row of db.prepare("SELECT id, config_encrypted FROM alert_destinations WHERE config_encrypted != ''").all()) {
      if (!isEncrypted(row.config_encrypted)) updateAlertDestination.run(encrypt(row.config_encrypted), row.id);
    }
  });
  transaction();
}

function rotateMasterKey(db) {
  const ring = loadKeyring();
  if (ring.external) throw new Error('Master-key rotation is controlled by SHAM_MASTER_KEY. Rotate the environment secret and restart using an overlapping keyring migration procedure.');
  const next = crypto.randomBytes(32);
  writeKeyring({ active: serializeKey(next), previous: [serializeKey(ring.active), ...ring.previous.map(serializeKey)].slice(0, 2) });
  keyring = { active: next, previous: [ring.active, ...ring.previous].slice(0, 2), external: false };

  const transaction = db.transaction(() => {
    for (const row of db.prepare('SELECT key, value FROM settings').all()) {
      if (isEncrypted(row.value)) db.prepare('UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?').run(encrypt(decrypt(row.value), next), row.key);
    }
    for (const row of db.prepare('SELECT plugin_id, key, value FROM plugin_settings').all()) {
      let parsed;
      try { parsed = JSON.parse(row.value); } catch { continue; }
      if (!isEncrypted(parsed)) continue;
      db.prepare('UPDATE plugin_settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE plugin_id = ? AND key = ?')
        .run(JSON.stringify(encrypt(decrypt(parsed), next)), row.plugin_id, row.key);
    }
    for (const row of db.prepare("SELECT site_id, token FROM site_cloudflare_tunnels WHERE token != ''").all()) {
      if (isEncrypted(row.token)) db.prepare('UPDATE site_cloudflare_tunnels SET token = ?, updated_at = CURRENT_TIMESTAMP WHERE site_id = ?').run(encrypt(decrypt(row.token), next), row.site_id);
    }
    for (const row of db.prepare('SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL AND totp_secret != ?').all('')) {
      if (isEncrypted(row.totp_secret)) db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(encrypt(decrypt(row.totp_secret), next), row.id);
    }
    for (const row of db.prepare("SELECT id, connection_value FROM database_profiles WHERE connection_value != ''").all()) {
      if (isEncrypted(row.connection_value)) db.prepare('UPDATE database_profiles SET connection_value = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(encrypt(decrypt(row.connection_value), next), row.id);
    }
    for (const row of db.prepare("SELECT site_id, key, value FROM site_env WHERE secret = 1 AND value != ''").all()) {
      if (isEncrypted(row.value)) db.prepare('UPDATE site_env SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE site_id = ? AND key = ?').run(encrypt(decrypt(row.value), next), row.site_id, row.key);
    }
    for (const row of db.prepare("SELECT id, config_encrypted FROM alert_destinations WHERE config_encrypted != ''").all()) {
      if (isEncrypted(row.config_encrypted)) db.prepare('UPDATE alert_destinations SET config_encrypted = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(encrypt(decrypt(row.config_encrypted), next), row.id);
    }
  });

  // If any of this throws, the keyring file on disk still has the previous
  // key (only written below on success), so either key version remains
  // decryptable after a crash — nothing further to do here but propagate.
  transaction();
  writeKeyring({ active: serializeKey(next), previous: [] });
  keyring = { active: next, previous: [], external: false };
  return { rotatedAt: new Date().toISOString() };
}

module.exports = {
  ENCRYPTED_PREFIX,
  KEYRING_PATH,
  isEncrypted,
  encrypt,
  decrypt,
  encryptedJson,
  decryptedJson,
  getSecretSetting,
  setSecretSetting,
  migrateKnownSecrets,
  rotateMasterKey
};
